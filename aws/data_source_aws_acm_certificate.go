package aws

import (
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/schema"
)

type byCreationDateDescending []*acm.CertificateDetail

func (b byCreationDateDescending) Len() int {
	return len(b)
}

func (b byCreationDateDescending) Less(i, j int) bool {
	iTs, jTs := timestamp(b[i]), timestamp(b[j])
	return jTs.Before(iTs)
}

func (b byCreationDateDescending) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func timestamp(cert *acm.CertificateDetail) time.Time {
	ret := cert.CreatedAt
	if ret == nil {
		ret = cert.ImportedAt
	}
	return *ret
}

func dataSourceAwsAcmCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceAwsAcmCertificateRead,
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:     schema.TypeString,
				Required: true,
			},
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"statuses": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"most_recent": {
				Type: schema.TypeBool,
				Optional: true,
				Default: false,
			},
		},
	}
}

func dataSourceAwsAcmCertificateRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).acmconn
	params := &acm.ListCertificatesInput{}

	target := d.Get("domain")

	statuses, ok := d.GetOk("statuses")
	if ok {
		statusStrings := statuses.([]interface{})
		params.CertificateStatuses = expandStringList(statusStrings)
	} else {
		params.CertificateStatuses = []*string{aws.String("ISSUED")}
	}

	var arns []string
	err := conn.ListCertificatesPages(params, func(page *acm.ListCertificatesOutput, lastPage bool) bool {
		for _, cert := range page.CertificateSummaryList {
			if *cert.DomainName == target {
				arns = append(arns, *cert.CertificateArn)
			}
		}

		return true
	})
	if err != nil {
		return errwrap.Wrapf("Error describing certificates: {{err}}", err)
	}

	var certDetails []*acm.CertificateDetail

	// filter based on certificate type (imported or aws-issued)
	types, ok := d.GetOk("types")
	if ok {
		typesStrings := expandStringList(types.([]interface{}))
		for _, arn := range arns {
			params := &acm.DescribeCertificateInput{}
			params.CertificateArn = &arn

			description, err := conn.DescribeCertificate(params)
			if err != nil {
				return errwrap.Wrapf("Error describing certificates: {{err}}", err)
			}

			for _, certType := range typesStrings {
				if *description.Certificate.Type == *certType {
					certDetails = append(certDetails, description.Certificate)
					break
				}
			}
		}
	}

	if len(certDetails) == 0 {
		return fmt.Errorf("No certificate for domain %q found in this region.", target)
	}

	mostRecent := d.Get("most_recent").(bool)
	if len(certDetails) > 1 && !mostRecent {
		return fmt.Errorf("Multiple certificates for domain %q found in this region.", target)
	}

	d.SetId(time.Now().UTC().String())
	sort.Sort(byCreationDateDescending(certDetails))
	d.Set("arn", *(certDetails[0].CertificateArn))

	return nil
}
