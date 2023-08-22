package signatures

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scorpio-id/pki/internal/config"
)

// FIXME - this csr contains SANS test.example.com and *.example.com
const CSR = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIIDZjCCAk4CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbl
UrNyz9CSQCZmomiOjrdVn9HiI+Tg13mtxaPEZCTwmO2w4YYKnNGiwpgTAP7JMr5n
Vd4UvR1LGAiDh+rLoSwB7XHo1SqHKgG+n8x3mwIohfoTla02ucotA9Y16lQaRqHb
rwwbhFRU9DPIL7wtrz6eioDbKJgAsIosa+CFRVL8TlH5ba+5q2pw9sJ7PzGtIdhA
bQKKn0TMqzHE6AA2G5mG6buILl1jHoqjiC1etP5WIWr48B3jzP7H0vUSrpliOF5B
s1VkXcaAIoagkpsyGxZNjEkgRvLAgLscSIxMRgUUGqDv6H/EpAjJGng0BXD6zLCa
ueEu+zKlO8b/GjB5qwECAwEAAaCCAR8wHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5
MDQ1LjIwKwYJKwYBBAGCNxUUMR4wHAIBBQwDTVNJDAlNU0lcYmptMzIMB01NQy5F
WEUwZgYKKwYBBAGCNw0CAjFYMFYCAQEeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMA
dAByAG8AbgBnACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYA
aQBkAGUAcgMBADBqBgkqhkiG9w0BCQ4xXTBbMCoGA1UdEQQjMCGCDSouZXhhbXBs
ZS5jb22CEHRlc3QuZXhhbXBsZS5jb20wHQYDVR0OBBYEFJ50P35zhfEeUVMwWRSH
viBAp6UmMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQUFAAOCAQEACdJIYKlI
+JigK87BYRy6JAOCVLzGckXm9BGBgd+CrEu+op34LRCHvg9bpUy28oYY2Ewqk3E1
WJtJtaHjYyu5zxjYcfVxm4gJl8e2yUfkOg5UKz/Yi9+yPGITZUOiOWR9pMoAXkLx
5bJTOVR20GqLnsQRPrEnqoxIv/PQL9MPic2Wqrx7ly4SbW606EkGwZ1K0AP7lV1x
4KREot3Ohrv37/m26Jg74qvRBffZoJYHTqPRS6kOPIHlJf0xOg1mS3LSPECUT6OW
H0mUWd2GC0FVhVvPumCwtypDtf5yLBesm/Gx39onIrVDk9frllFH1+ap6MP12VEE
lk+Ij1pb7T4Y7A==
-----END NEW CERTIFICATE REQUEST-----`

func TestSignX509Certificate(t *testing.T) {
	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("non-200 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateDuplicateError(t *testing.T) {
	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../config/test.yml")

	s := NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := http.Client{}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header?
	writer.Close()

	req, err := http.NewRequest("POST", server.URL+"/certificate", &buf)
	if err != nil {
		t.Error(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, err = client.Do(req)
	if err != nil {
		t.Error(err)
	}

	// send duplicate request and assert error
	buf.Reset()
	writer.WriteField("csr", CSR)

	// writer must be closed to correctly calculate boundary in multipart form request header?
	writer.Close()

	response, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}

	if response.StatusCode != 400 {
		t.Fatalf("non-400 status code: [%v]", response.StatusCode)
	}
}

func TestSignX509CertificateWildcardDuplicateError(t *testing.T) {
	// TODO - attempt to sign cert with fail.example.com while *.example.com is already registered
	// create another CSR with desired san fail.example.com
}

func TestSignX509CertificateAllowedPolicyError(t *testing.T) {
	// TODO - attempt to sign cert not explicitly allowed by policy configuration
}
