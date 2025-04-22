package registrar

import (
	"database/sql"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	_ "modernc.org/sqlite"
)

type DAO struct {
	db *sql.DB
}

func (d *DAO) Close() error {
	err := d.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close attestation database: %v", err)
	}
	return nil
}

func (d *DAO) Open(dataSourceName string) error {
	var err error
	d.db, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		return fmt.Errorf("failed to open registrar db: %v", err)
	}
	return nil
}

func (d *DAO) initCACertificates() error {
	// Prepare the insert statement
	insertCertificateQuery := `INSERT INTO tpm_ca_certificates (commonName, pemCertificate) VALUES (?, ?);`
	query, err := d.db.Prepare(insertCertificateQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, caCertificate := range getKnownTPMCACertificates() {
		_, err := query.Exec(caCertificate.CommonName, caCertificate.PEMCertificate)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", caCertificate.CommonName, err)
		}
	}
	return nil
}

func (d *DAO) initTPMVendors() error {
	// Prepare the insert statement
	insertVendorQuery := `INSERT INTO tpm_vendors (name, tcgIdentifier) VALUES (?, ?);`
	query, err := d.db.Prepare(insertVendorQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, vendor := range getKnownTPMManufacturers() {
		_, err := query.Exec(vendor.CommonName, vendor.TCGIdentifier)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", vendor.CommonName, err)
		}
	}
	return nil
}

// Init sets up the database and creates necessary tables if they don't exist.
func (d *DAO) Init() error {
	var err error
	// Create workers table
	createWorkerTableQuery := `
	CREATE TABLE IF NOT EXISTS workers (
		UUID TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		AIK TEXT NOT NULL UNIQUE
	);`
	if _, err = d.db.Exec(createWorkerTableQuery); err != nil {
		return fmt.Errorf("failed to create workers table: %w", err)
	}

	// Create TPM Certificates table
	createTPMCertTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_ca_certificates (
		certificateId INTEGER PRIMARY KEY AUTOINCREMENT,
		commonName TEXT NOT NULL UNIQUE,
		pemCertificate TEXT NOT NULL UNIQUE
	);`

	if _, err = d.db.Exec(createTPMCertTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM certificates table: %w", err)
	}

	// Create TPM Certificates table
	createTPMVendorTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_vendors (
		vendorId INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		tcgIdentifier TEXT NOT NULL UNIQUE
	);`

	if _, err = d.db.Exec(createTPMVendorTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM vendors table: %w", err)
	}

	err = d.initTPMVendors()
	if err != nil {
		return fmt.Errorf("failed to insert default TPM vendors: %v", err)
	}

	err = d.initCACertificates()
	if err != nil {
		return fmt.Errorf("failed to insert known CA certificates: %v", err)
	}
	return nil
}

// TPMManufacturers TCG recognized TPM manufacturers
// https://trustedcomputinggroup.org/resource/vendor-id-registry/
func getKnownTPMManufacturers() []model.TPMVendor {
	return []model.TPMVendor{
		{CommonName: "AMD", TCGIdentifier: "id:414D4400"},
		{CommonName: "Atmel", TCGIdentifier: "id:41544D4C"},
		{CommonName: "Broadcom", TCGIdentifier: "id:4252434D"},
		{CommonName: "Cisco", TCGIdentifier: "id:4353434F"},
		{CommonName: "Flyslice Technologies", TCGIdentifier: "id:464C5953"},
		{CommonName: "HPE", TCGIdentifier: "id:48504500"},
		{CommonName: "Huawei", TCGIdentifier: "id:48495349"},
		{CommonName: "IBM", TCGIdentifier: "id:49424D00"},
		{CommonName: "Infineon", TCGIdentifier: "id:49465800"},
		{CommonName: "Intel", TCGIdentifier: "id:494E5443"},
		{CommonName: "Lenovo", TCGIdentifier: "id:4C454E00"},
		{CommonName: "Microsoft", TCGIdentifier: "id:4D534654"},
		{CommonName: "National Semiconductor", TCGIdentifier: "id:4E534D20"},
		{CommonName: "Nationz", TCGIdentifier: "id:4E545A00"},
		{CommonName: "Nuvoton Technology", TCGIdentifier: "id:4E544300"},
		{CommonName: "Qualcomm", TCGIdentifier: "id:51434F4D"},
		{CommonName: "SMSC", TCGIdentifier: "id:534D5343"},
		{CommonName: "ST Microelectronics", TCGIdentifier: "id:53544D20"},
		{CommonName: "Samsung", TCGIdentifier: "id:534D534E"},
		{CommonName: "Sinosun", TCGIdentifier: "id:534E5300"},
		{CommonName: "Texas Instruments", TCGIdentifier: "id:54584E00"},
		{CommonName: "Winbond", TCGIdentifier: "id:57454300"},
		{CommonName: "Fuzhouk Rockchip", TCGIdentifier: "id:524F4343"},
		{CommonName: "Google", TCGIdentifier: "id:474F4F47"},
	}
}

func getKnownTPMCACertificates() []model.TPMCACertificate {
	return []model.TPMCACertificate{
		{CommonName: "Infineon OPTIGA(TM) RSA Manufacturing CA 003", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFszCCA5ugAwIBAgIEasM5FDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJE\nRTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJP\nUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkg\nUlNBIFJvb3QgQ0EwHhcNMTQxMTI0MTUzNzE2WhcNMzQxMTI0MTUzNzE2WjCBgzEL\nMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEa\nMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9Q\nVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuUD5SLLVYRmuxDjT3cWQbRTywTWUVFE3EupJQZjJ\n9mvFc2KcjpQv6rpdaT4JC33P1M9iJgrHwYO0AZlGl2FcFpSNkc/3CWoMTT9rOdwS\n/MxlNSkxwTz6IAYUYh7+pd7T49NpRRGZ1dOMfyOxWgA4C0g3EP/ciIvA2cCZ95Hf\nARD9NhuG2DAEYGNRSHY2d/Oxu+7ytzkGFFj0h1jnvGNJpWNCf3CG8aNc5gJAduMr\nWcaMHb+6fWEysg++F2FLav813+/61FqvSrUMsQg0lpE16KBA5QC2Wcr/kLZGVVGc\nuALtgJ/bnd8XgEv7W8WG+jyblUe+hkZWmxYluHS3yJeRbwIDAQABo4IBODCCATQw\nVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vcGtpLmluZmluZW9u\nLmNvbS9PcHRpZ2FSc2FSb290Q0EvT3B0aWdhUnNhUm9vdENBLmNydDAdBgNVHQ4E\nFgQUQLhoK40YRQorBoSdm1zZb0zd9L4wDgYDVR0PAQH/BAQDAgAGMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL3BraS5pbmZpbmVv\nbi5jb20vT3B0aWdhUnNhUm9vdENBL09wdGlnYVJzYVJvb3RDQS5jcmwwFQYDVR0g\nBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBTcu1ar8Rj8ppp1ERBlhBKe1UGS\nuTAQBgNVHSUECTAHBgVngQUIATANBgkqhkiG9w0BAQsFAAOCAgEAeUzrsGq3oQOT\nmF7g71TtMMndwPxgZvaB4bAc7dNettn5Yc1usikERfvJu4/iBs/Tdl6z6TokO+6V\nJuBb6PDV7f5MFfffeThraPCTeDcyYBzQRGnoCxc8Kf81ZJT04ef8CQkkfuZHW1pO\n+HHM1ZfFfNdNTay1h83x1lg1U0KnlmJ5KCVFiB94owr9t5cUoiSbAsPcpqCrWczo\nRsg1aTpokwI8Y45lqgt0SxEmQw2PIAEjHG2GQcLBDeI0c7cK5OMEjSMXStJHmNbp\nu4RHXzd+47nCD2kGV8Bx5QnK8qDVAFAe/UTDQi5mTtDFRL36Nns7jz8USemu+bw9\nl24PN73rKcB2wNF2/oFTLPHkdYfTKYGXG1g2ZkDcTAENSOq3fcTfAuyHQozBwYHG\nGGyyPHy6KvLkqMQuqeDv0QxGOtE+6cedFMP2D9bMaujR389mSm7DE6YyNQClRW7w\nJ1+rNYuN2vErvB96ir1zljXq0yMxrm5nTeiAT4p5eoFqoeSYDbFljt/f+PebREiO\nnJIy4fdvKlHAf70gPdYpYipc4oTZxLeWjDQxRFFBDFrnLdlPSg6zSL2Q3ANAEI3y\nMtHaEaU0wbaBvezyzMUHI5nLnYFL+QRP4N2OFNI/ejBaEpmIXzf6+/eF40MNLHuR\n9/B93Q+hpw8O6XZ7qx697I+5+smLlPQ=\n-----END CERTIFICATE-----"},
		{CommonName: "Infineon OPTIGA(TM) RSA Root CA", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh\nMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\nR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB\nIFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD\nVQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD\nVQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH\nQShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn\n25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr\nR3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS\nJRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT\nZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl\n8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2\n7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1\nbdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d\ncAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS\nghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu\n81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV\nHQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN\nUltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M\nBdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y\nrkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ\ngGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y\nnp8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2\nDvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr\nla5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf\nRdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR\npubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv\nJpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM\n6sJa8iBpdRjZrBp5sJBI\n-----END CERTIFICATE-----"},
	}
}

// Utility function: Check if a worker already exists by name
func (d *DAO) workerExistsByAIK(aik string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE AIK = ?;"
	err := d.db.QueryRow(query, aik).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a worker already exists by name
func (d *DAO) workerExistsByUUID(uuid string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE UUID = ?;"
	err := d.db.QueryRow(query, uuid).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (d *DAO) AddWorker(worker *model.WorkerNode) error {
	query := "INSERT INTO workers (UUID, name, AIK) VALUES (?, ?, ?);"
	_, err := d.db.Exec(query, worker.UUID, worker.Name, worker.AIK)
	return err
}

func (d *DAO) DeleteWorker(UUID string) error {
	query := "DELETE FROM workers WHERE UUID = ?;"
	_, err := d.db.Exec(query, UUID)
	return err
}

func (d *DAO) GetWorkerByUUID(UUID string) (*model.WorkerNode, error) {
	var worker model.WorkerNode
	query := "SELECT * FROM workers WHERE UUID = ?;"
	err := d.db.QueryRow(query, UUID).Scan(&worker.UUID, &worker.Name, &worker.AIK)
	if err != nil {
		return nil, err
	}
	return &worker, nil
}

func (d *DAO) GetWorkerByName(name string) (*model.WorkerNode, error) {
	var worker model.WorkerNode
	query := "SELECT * FROM workers WHERE name = ?;"
	err := d.db.QueryRow(query, name).Scan(&worker.UUID, &worker.Name, &worker.AIK)
	if err != nil {
		return nil, err
	}
	return &worker, nil
}

func (d *DAO) AddTPMCaCertificate(certificate *model.TPMCACertificate) error {
	query := "INSERT INTO tpm_ca_certificates (commonName, pemCertificate) VALUES (?, ?);"
	_, err := d.db.Exec(query, certificate.CommonName, certificate.PEMCertificate)
	return err
}

func (d *DAO) DeleteTPMCaCertificate(commonName string) error {
	query := "DELETE FROM tpm_ca_certificates WHERE commonName = ?;"
	_, err := d.db.Exec(query, commonName)
	return err
}

func (d *DAO) GetAllWorkers() ([]model.WorkerNode, error) {
	var workers []model.WorkerNode
	query := "SELECT * FROM workers ORDER BY name;"
	err := d.db.QueryRow(query).Scan(&workers)
	if err != nil {
		return nil, err
	}
	return workers, nil
}

func (d *DAO) GetAllTPMCaCertificates() ([]model.TPMCACertificate, error) {
	query := "SELECT * FROM tpm_ca_certificates;"
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}

	defer func(rows *sql.Rows) {
		err = rows.Close()
		if err != nil {
			return
		}
	}(rows)

	var certs []model.TPMCACertificate
	for rows.Next() {
		var cert model.TPMCACertificate
		err = rows.Scan(&cert.Id, &cert.CommonName, &cert.PEMCertificate)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return certs, nil
}

func (d *DAO) GetTPMCaCertificate(commonName string) (*model.TPMCACertificate, error) {
	var cert model.TPMCACertificate
	query := "SELECT * FROM tpm_ca_certificates WHERE commonName = ?;"
	err := d.db.QueryRow(query, commonName).Scan(&cert.Id, &cert.CommonName, &cert.PEMCertificate)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (d *DAO) GetAllTPMVendors() ([]model.TPMVendor, error) {
	query := "SELECT * FROM tpm_vendors;"
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	var tpmVendors []model.TPMVendor
	for rows.Next() {
		var vendor model.TPMVendor
		err = rows.Scan(&vendor.Id, &vendor.CommonName, &vendor.TCGIdentifier)
		if err != nil {
			return nil, err
		}
		tpmVendors = append(tpmVendors, vendor)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return tpmVendors, nil
}

func (d *DAO) GetTPMVendorByTCGId(tcgIdentifier string) (*model.TPMVendor, error) {
	var tpmVendor model.TPMVendor
	query := "SELECT * FROM tpm_vendors WHERE TCGIdentifier = ?;"
	err := d.db.QueryRow(query, tcgIdentifier).Scan(&tpmVendor.Id, &tpmVendor.CommonName, &tpmVendor.TCGIdentifier)
	if err != nil {
		return nil, err
	}
	return &tpmVendor, err
}
