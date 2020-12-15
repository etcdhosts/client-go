package client

import (
	"testing"
	"time"
)

func getExampleHosts() (*Hostsfile, error) {
	return NewHostFile(EtcdConfig{
		CA:   "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZyakNDQ...",
		Cert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZNekNDQ...",
		Key:  "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFc...",
		Endpoints: []string{
			"https://172.16.1.21:2379",
			"https://172.16.1.22:2379",
			"https://172.16.1.23:2379",
		},
		HostsKey:    "/etcdhosts",
		DialTimeout: 5 * time.Second,
		ReqTimeout:  5 * time.Second,
	})
}

func TestHostsfile_ReadHosts(t *testing.T) {
	hf, err := getExampleHosts()
	if err != nil {
		t.Fatal(err)
	}
	hf.ReadHosts()
	t.Log(hf.hmap)
}

func TestHostsfile_AddHost(t *testing.T) {
	hf, err := getExampleHosts()
	if err != nil {
		t.Fatal(err)
	}
	hf.ReadHosts()
	err = hf.AddHost("baidu.com", "1.1.1.1", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
	err = hf.AddHost("baidu.com", "::0202:0202", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
}

func TestHostsfile_DelHost(t *testing.T) {
	hf, err := getExampleHosts()
	if err != nil {
		t.Fatal(err)
	}
	hf.ReadHosts()

	err = hf.DelHost("baidu.com", "::0202:0202")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
	err = hf.DelHost("baidu.com", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
}
