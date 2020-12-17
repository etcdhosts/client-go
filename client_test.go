package client

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func newExampleClient() (*Client, error) {
	return NewClient(Config{
		CA:          os.Getenv("ETCD_CA"),
		Cert:        os.Getenv("ETCD_CERT"),
		Key:         os.Getenv("ETCD_KEY"),
		Endpoints:   strings.Split(os.Getenv("ETCD_ENDPOINTS"), ","),
		HostsKey:    "/etcdhosts",
		DialTimeout: 5 * time.Second,
		ReqTimeout:  5 * time.Second,
	})
}

func TestClient_ReadHosts(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := cli.ReadHosts()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.version)
	t.Log(hf.hmap)
}

func TestClient_GetHistoryHosts(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hfs, err := cli.GetHostsHistory()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(hfs))
}

func TestHostsfile_AddHost(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := cli.ReadHosts()
	if err != nil {
		t.Fatal(err)
	}
	err = hf.AddHost("baidu.com", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
	err = hf.AddHost("baidu.com", "::0202:0202")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hf.hmap)
}

func TestHostsfile_DelHost(t *testing.T) {
	hf := &Hostsfile{
		hmap:    newMap(),
		version: 1,
	}
	hf.hmap.name4["baidu.com."] = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("3.3.3.3")}
	hf.hmap.name6["baidu.com."] = []net.IP{net.ParseIP("::0202:0202")}

	err := hf.DelHost("baidu.com", "::0202:0202")
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

func TestClient_PutHost(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := cli.ReadHosts()
	if err != nil {
		t.Fatal(err)
	}
	err = hf.AddHost("baidu.com", "1.2.3.12")
	if err != nil {
		t.Fatal(err)
	}
	err = cli.PutHost(hf)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostsfile_SearchHost(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := cli.ReadHosts()
	if err != nil {
		t.Fatal(err)
	}
	ips := hf.SearchHost("baidu.com")
	t.Log(ips)
}

func TestHostsfile_PurgeHost(t *testing.T) {
	cli, err := newExampleClient()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := cli.ReadHosts()
	if err != nil {
		t.Fatal(err)
	}
	hf.PurgeHost("baidu.com")
	t.Log(hf.hmap)
}
