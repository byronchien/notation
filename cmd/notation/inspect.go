package main

import (
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/notaryproject/notation/internal/ioutil"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
)

const (
	treeItemPrefix     = "├──"
	treeItemPrefixLast = "└──"
	subTreePrefix      = "│  "
	subTreePrefixLast  = "   "
)

type inspectOpts struct {
	cmd.LoggingFlagOpts
	SecureFlagOpts
	reference    string
	outputFormat string
}

type inspectOutput struct {
	MediaType  string `json:"mediaType"`
	Signatures []signatureOutput
}

type signatureOutput struct {
	Digest                string              `json:"digest"`
	SignatureAlgorithm    string              `json:"signatureAlgorithm"`
	SignedAttributes      map[string]string   `json:"signedAttributes"`
	UserDefinedAttributes map[string]string   `json:"userDefinedAttributes"`
	UnsignedAttributes    map[string]string   `json:"unsignedAttributes"`
	Certificates          []certificateOutput `json:"certificates"`
	SignedArtifact        artifact            `json:"signedArtifact"`
}

type certificateOutput struct {
	SHA1Fingerprint string `json:"SHA1Fingerprint"`
	IssuedTo        string `json:"issuedTo"`
	IssuedBy        string `json:"issuedBy"`
	Expiry          string `json:"expiry"`
}

type artifact struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func inspectCommand(opts *inspectOpts) *cobra.Command {
	if opts == nil {
		opts = &inspectOpts{}
	}
	command := &cobra.Command{
		Use:   "inspect [reference]",
		Short: "Inspect all signatures associated with the signed artifact",
		Long:  "Inspect all signatures associated with the signed artifact.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference")
			}
			opts.reference = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(cmd, opts)
		},
	}

	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	cmd.SetPflagOutput(command.Flags(), &opts.outputFormat, cmd.PflagOutputUsage)
	return command
}

func runInspect(command *cobra.Command, opts *inspectOpts) error {
	// set log level
	ctx := opts.LoggingFlagOpts.SetLoggerLevel(command.Context())

	if opts.outputFormat != ioutil.OutputJson && opts.outputFormat != ioutil.OutputPlaintext {
		return fmt.Errorf("unrecognized output format %s", opts.outputFormat)
	}

	// initialize
	reference := opts.reference
	sigRepo, err := getSignatureRepository(ctx, &opts.SecureFlagOpts, reference)
	if err != nil {
		return err
	}

	manifestDesc, ref, err := getManifestDescriptor(ctx, &opts.SecureFlagOpts, reference, sigRepo)
	if err != nil {
		return err
	}

	// reference is a digest reference
	if err := ref.ValidateReferenceAsDigest(); err != nil {
		if opts.outputFormat == ioutil.OutputPlaintext {
			fmt.Printf("Resolved artifact tag `%s` to digest `%s` before inspect.\n", ref.Reference, manifestDesc.Digest.String())
			fmt.Println("Warning: The resolved digest may not point to the same signed artifact, since tags are mutable.")
		}
		ref.Reference = manifestDesc.Digest.String()
	}

	if opts.outputFormat == ioutil.OutputPlaintext {
		fmt.Println("Inspecting all signatures for signed artifact")
		fmt.Println(ref.String())
	}

	output := inspectOutput{MediaType: manifestDesc.MediaType, Signatures: []signatureOutput{}}

	err = sigRepo.ListSignatures(ctx, manifestDesc, func(signatureManifests []ocispec.Descriptor) error {
		for _, sigManifestDesc := range signatureManifests {
			sigBlob, sigDesc, err := sigRepo.FetchSignatureBlob(ctx, sigManifestDesc)
			if err != nil {
				return fmt.Errorf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %v", sigManifestDesc.Digest, manifestDesc.Digest, err.Error())
			}

			envelope, err := signature.ParseEnvelope(sigDesc.MediaType, sigBlob)
			envelopeContent, err := envelope.Content()
			if err != nil {
				return err
			}

			signedArtifactDesc, err := notation.GetDescriptorFromPayload(&envelopeContent.Payload)
			if err != nil {
				return err
			}

			sig := signatureOutput{
				Digest:                sigDesc.Digest.String(),
				SignatureAlgorithm:    envelopeContent.SignerInfo.SignatureAlgorithm.String(),
				SignedAttributes:      getSignedAttributes(envelopeContent),
				UserDefinedAttributes: signedArtifactDesc.Annotations,
				UnsignedAttributes:    getUnsignedAttributes(envelopeContent),
				Certificates:          getCertificates(envelopeContent),
				SignedArtifact: artifact{
					MediaType: signedArtifactDesc.MediaType,
					Digest:    signedArtifactDesc.Digest.String(),
					Size:      signedArtifactDesc.Size,
				},
			}

			output.Signatures = append(output.Signatures, sig)
		}
		return nil
	})

	if err != nil {
		return err
	}

	return printOutput(opts.outputFormat, output)
}

func getSignedAttributes(envContent *signature.EnvelopeContent) map[string]string {
	signedAttributes := map[string]string{}

	signedAttributes["signingScheme"] = string(envContent.SignerInfo.SignedAttributes.SigningScheme)
	signedAttributes["signingTime"] = envContent.SignerInfo.SignedAttributes.SigningTime.String()
	signedAttributes["expiry"] = envContent.SignerInfo.SignedAttributes.Expiry.String()

	for _, attribute := range envContent.SignerInfo.SignedAttributes.ExtendedAttributes {
		if key, ok := attribute.Key.(string); ok {
			if value, ok := attribute.Value.(string); ok {
				signedAttributes[key] = value
			}
		}
	}

	return signedAttributes
}

func getUnsignedAttributes(envContent *signature.EnvelopeContent) map[string]string {
	unsignedAttributes := map[string]string{}

	if envContent.SignerInfo.UnsignedAttributes.TimestampSignature != nil {
		unsignedAttributes["timestampSignature"] = string(envContent.SignerInfo.UnsignedAttributes.TimestampSignature)
	}

	if envContent.SignerInfo.UnsignedAttributes.SigningAgent != "" {
		unsignedAttributes["signingAgent"] = envContent.SignerInfo.UnsignedAttributes.SigningAgent
	}

	return unsignedAttributes
}

func getCertificates(envContent *signature.EnvelopeContent) []certificateOutput {
	certificates := []certificateOutput{}

	for _, cert := range envContent.SignerInfo.CertificateChain {
		h := sha1.New()
		h.Write(cert.RawTBSCertificate)
		fingerprint := fmt.Sprintf("%x", h.Sum(nil))

		certificate := certificateOutput{
			SHA1Fingerprint: fingerprint,
			IssuedTo:        cert.Subject.String(),
			IssuedBy:        cert.Issuer.String(),
			Expiry:          cert.NotAfter.String(),
		}

		certificates = append(certificates, certificate)
	}

	return certificates
}

func printOutput(outputFormat string, output inspectOutput) error {
	if outputFormat == ioutil.OutputJson {
		return ioutil.PrintObjectAsJson(output)
	}

	fmt.Println("└── application/vnd.cncf.notary.signature")

	for n, signature := range output.Signatures {
		sigTree := treeItemPrefix
		sigTreePrefix := subTreePrefix
		if n == len(output.Signatures)-1 {
			sigTree = treeItemPrefixLast
			sigTreePrefix = subTreePrefixLast
		}

		fmt.Printf("    %s %s\n", sigTree, signature.Digest)

		sigSubTree := treeItemPrefix
		sigSubTreePrefix := subTreePrefix

		fmt.Printf("    %s %s %s : %s\n", sigTreePrefix, sigSubTree, "signature algorithm", signature.SignatureAlgorithm)

		fmt.Printf("    %s %s %s\n", sigTreePrefix, sigSubTree, "signed attributes")
		prefix := fmt.Sprintf("    %s %s", sigTreePrefix, sigSubTreePrefix)
		printMapAsTree(prefix, signature.SignedAttributes)

		fmt.Printf("    %s %s %s\n", sigTreePrefix, sigSubTree, "user defined attributes")
		printMapAsTree(prefix, signature.UserDefinedAttributes)

		fmt.Printf("    %s %s %s\n", sigTreePrefix, sigSubTree, "unsigned attributes")
		printMapAsTree(prefix, signature.UnsignedAttributes)

		fmt.Printf("    %s %s %s\n", sigTreePrefix, sigSubTree, "certificates")
		for k, cert := range signature.Certificates {
			certTreePrefix := treeItemPrefix
			certSubTreePrefix := subTreePrefix
			if k == len(signature.Certificates)-1 {
				certTreePrefix = treeItemPrefixLast
				certSubTreePrefix = subTreePrefixLast
			}

			fmt.Printf("    %s %s %s SHA1 fingerprint %s\n", sigTreePrefix, sigSubTreePrefix, certTreePrefix, cert.SHA1Fingerprint)
			fmt.Printf("    %s %s %s ├── issued to : %s\n", sigTreePrefix, sigSubTreePrefix, certSubTreePrefix, cert.IssuedTo)
			fmt.Printf("    %s %s %s ├── issued by : %s\n", sigTreePrefix, sigSubTreePrefix, certSubTreePrefix, cert.IssuedBy)
			fmt.Printf("    %s %s %s └── expiry : %s\n", sigTreePrefix, sigSubTreePrefix, certSubTreePrefix, cert.Expiry)
		}

		sigSubTree = treeItemPrefixLast
		sigSubTreePrefix = subTreePrefixLast
		fmt.Printf("    %s %s %s\n", sigTreePrefix, sigSubTree, "signed artifact")
		fmt.Printf("    %s %s ├── media type : %s\n", sigTreePrefix, sigSubTreePrefix, signature.SignedArtifact.MediaType)
		fmt.Printf("    %s %s ├── digest : %s\n", sigTreePrefix, sigSubTreePrefix, signature.SignedArtifact.Digest)
		fmt.Printf("    %s %s └── size : %d\n", sigTreePrefix, sigSubTreePrefix, signature.SignedArtifact.Size)
	}

	return nil
}

func printMapAsTree(prefix string, m map[string]string) {
	mapSize := len(m)
	index := 0

	for k, v := range m {
		mapPrefix := treeItemPrefix
		if index == mapSize-1 {
			mapPrefix = treeItemPrefixLast
		}

		fmt.Printf("%s %s %s : %s\n", prefix, mapPrefix, k, v)
		index += 1
	}
}
