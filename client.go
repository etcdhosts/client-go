package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"

	"go.etcd.io/etcd/clientv3/concurrency"

	"github.com/mritd/logger"

	"go.etcd.io/etcd/clientv3"
)

type Client struct {
	// etcd v3 client
	etcdClient *clientv3.Client

	// etcd client timeout
	etcdTimeout time.Duration

	// etcd key
	etcdHostsKey string
}

func (cli *Client) ReadHostsFile() (*HostsFile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cli.etcdTimeout)
	defer cancel()
	getResp, err := cli.etcdClient.Get(ctx, cli.etcdHostsKey, clientv3.WithFirstRev()...)
	if err != nil {
		logger.Errorf("failed to get etcd key [%s]: %s", cli.etcdHostsKey, err.Error())
		return nil, fmt.Errorf("failed to get etcd key [%s]: %s", cli.etcdHostsKey, err.Error())
	}

	if len(getResp.Kvs) != 1 {
		logger.Errorf("invalid etcd response: %d", len(getResp.Kvs))
		return nil, fmt.Errorf("invalid etcd response: %d", len(getResp.Kvs))
	}

	return &HostsFile{
		hmap:    Parse2Map(bytes.NewReader(getResp.Kvs[0].Value)),
		version: getResp.Kvs[0].Version,
	}, nil
}

func (cli *Client) GetHostsFileHistory() ([]*HostsFile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cli.etcdTimeout)
	defer cancel()
	getResp, err := cli.etcdClient.Get(ctx, cli.etcdHostsKey)
	if err != nil {
		logger.Errorf("failed to get etcd key [%s]: %s", cli.etcdHostsKey, err.Error())
		return nil, fmt.Errorf("failed to get etcd key [%s]: %s", cli.etcdHostsKey, err.Error())
	}
	if len(getResp.Kvs) != 1 {
		logger.Errorf("invalid etcd response: %d", len(getResp.Kvs))
		return nil, fmt.Errorf("invalid etcd response: %d", len(getResp.Kvs))
	}

	var hfs []*HostsFile
	for i := getResp.Header.Revision; i > 0; i-- {
		getCtx, getCancel := context.WithTimeout(context.Background(), cli.etcdTimeout)
		resp, err := cli.etcdClient.Get(getCtx, cli.etcdHostsKey, clientv3.WithRev(i))
		if err != nil {
			getCancel()
			break
		}
		i = resp.Kvs[0].ModRevision
		hfs = append(hfs, &HostsFile{
			hmap:    Parse2Map(bytes.NewReader(resp.Kvs[0].Value)),
			version: resp.Kvs[0].Version,
		})
		getCancel()
	}
	return hfs, nil
}

func (cli *Client) PutHostsFile(hf *HostsFile) error {
	seCtx, cancel := context.WithTimeout(context.Background(), cli.etcdTimeout)
	defer cancel()

	session, err := concurrency.NewSession(cli.etcdClient, concurrency.WithContext(seCtx))
	if err != nil {
		return fmt.Errorf("failed to create etcd session: %w", err)
	}
	defer func() { _ = session.Close() }()

	mux := concurrency.NewMutex(session, cli.etcdHostsKey)
	err = mux.Lock(context.Background())
	defer func() { _ = mux.Unlock(context.Background()) }()
	if err != nil {
		return fmt.Errorf("failed to lock etcd hosts key: %w", err)
	}
	shf, err := cli.ReadHostsFile()
	if err != nil {
		return fmt.Errorf("failed to read etcd hosts: %w", err)
	}

	if shf.version > hf.version {
		return fmt.Errorf("the hostsfile in the database has been updated, please obtain a copy of the hostsfile again: db version: %d, put version: %d", shf.version, hf.version)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.etcdTimeout)
	defer cancel()

	hf.Lock()
	defer hf.Unlock()
	_, err = cli.etcdClient.Put(ctx, cli.etcdHostsKey, hf.hmap.String())
	if err != nil {
		return fmt.Errorf("etcd client error: %w", err)
	}
	return nil
}

func (cli *Client) ForcePutHostsFile(r io.Reader) error {
	return cli.PutHostsFile(&HostsFile{
		hmap:    Parse2Map(r),
		version: math.MaxInt64,
	})
}

func NewClient(c Config) (*Client, error) {
	if c.Cert == "" || c.Key == "" {
		return nil, fmt.Errorf("[etcd] certs config is empty")
	}

	if len(c.Endpoints) < 1 {
		return nil, fmt.Errorf("[etcd] endpoints config is empty")
	}

	var caBs, certBs, keyBs []byte

	// if config is filepath, replace "~" to real home dir
	home, err := homedir.Dir()
	if err != nil {
		return nil, fmt.Errorf("[etcd] failed to get home dir: %w", err)
	}

	if strings.HasPrefix(c.CA, "~") {
		c.CA = strings.Replace(c.CA, "~", home, 1)
	}
	if strings.HasPrefix(c.Cert, "~") {
		c.Cert = strings.Replace(c.Cert, "~", home, 1)
	}
	if strings.HasPrefix(c.Key, "~") {
		c.Key = strings.Replace(c.Key, "~", home, 1)
	}

	// check config is base64 data or filepath
	_, err = os.Stat(c.Cert)
	if err == nil {
		certBs, err = ioutil.ReadFile(c.Cert)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] read cert file %s failed: %w", c.Cert, err)
		}
	} else {
		certBs, err = base64.StdEncoding.DecodeString(c.Cert)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] cert base64 decode failed: %w", err)
		}
	}

	_, err = os.Stat(c.Key)
	if err == nil {
		keyBs, err = ioutil.ReadFile(c.Key)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] read key file %s failed: %w", c.Key, err)
		}
	} else {
		keyBs, err = base64.StdEncoding.DecodeString(c.Key)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] key base64 decode failed: %w", err)
		}
	}

	etcdClientCert, err := tls.X509KeyPair(certBs, keyBs)
	if err != nil {
		return nil, fmt.Errorf("[etcd/cert] x509 error: %w", err)
	}

	var rootCertPool *x509.CertPool
	if c.CA != "" {
		_, err = os.Stat(c.CA)
		if err == nil {
			caBs, err = ioutil.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("[etcd/cert] read ca file %s failed: %w", c.CA, err)
			}
		} else {
			caBs, err = base64.StdEncoding.DecodeString(c.CA)
			if err != nil {
				return nil, fmt.Errorf("[etcd/cert] ca base64 decode failed: %w", err)
			}
		}

		rootCertPool = x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(caBs)
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   c.Endpoints,
		DialTimeout: c.DialTimeout,
		TLS: &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: []tls.Certificate{etcdClientCert},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("[etcd/client] create etcd client failed: %w", err)
	}

	return &Client{
		etcdClient:   cli,
		etcdTimeout:  c.ReqTimeout,
		etcdHostsKey: c.HostsKey,
	}, nil
}
