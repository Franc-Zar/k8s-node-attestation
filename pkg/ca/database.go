package ca

import (
	"database/sql"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/model"
	_ "modernc.org/sqlite"
)

type DAO struct {
	db *sql.DB
}

// Close closes the database connection
func (d *DAO) Close() error {
	err := d.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close Root CA database: %v", err)
	}
	return nil
}

// Open opens the database connection
func (d *DAO) Open(dataSourceName string) error {
	var err error
	d.db, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		return fmt.Errorf("failed to open Root CA database: %v", err)
	}
	return nil
}

func (d *DAO) Init() error {
	var err error
	// Table for issued certificates
	createIssuedCertsTableQuery := `
	CREATE TABLE IF NOT EXISTS issued_certificates (
		serial_number INTEGER PRIMARY KEY,
		common_name TEXT NOT NULL,
		certificate_pem TEXT NOT NULL,
		issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err = d.db.Exec(createIssuedCertsTableQuery); err != nil {
		return fmt.Errorf("failed to create issued_certificates table: %w", err)
	}

	// Table for revoked test-data / CRL entries
	createCRLsTableQuery := `
	CREATE TABLE IF NOT EXISTS crls (
		serial_number INTEGER PRIMARY KEY,
		crl_pem TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err = d.db.Exec(createCRLsTableQuery); err != nil {
		return fmt.Errorf("failed to create crls table: %w", err)
	}

	// Table for root CA material
	createRootCATableQuery := `
	CREATE TABLE IF NOT EXISTS root_ca (
	    serial_number INTEGER PRIMARY KEY,
	    common_name TEXT NOT NULL,
		ca_cert_pem TEXT NOT NULL,
		ca_key_pem TEXT NOT NULL
	);`
	if _, err = d.db.Exec(createRootCATableQuery); err != nil {
		return fmt.Errorf("failed to create root_ca table: %w", err)
	}
	return nil
}

// StoreRootCA stores the root CA material (certificate and private key)
func (d *DAO) StoreRootCA(caCert *model.Certificate, caKeyPEM []byte) error {
	_, err := d.db.Exec(`
	INSERT INTO root_ca (serial_number, common_name, ca_cert_pem, ca_key_pem)
	VALUES (?, ?)`, caCert.Id, caCert.CommonName, caCert.PEMCertificate, caKeyPEM)
	return err
}

func (d *DAO) GetRootCACert() (*model.Certificate, error) {
	var caCert model.Certificate
	err := d.db.QueryRow(`SELECT serial_number, common_name, ca_cert_pem FROM root_ca LIMIT 1`).Scan(&caCert.Id, &caCert.CommonName, &caCert.PEMCertificate)
	if err != nil {
		return nil, err
	}
	return &caCert, nil
}

// GetRootCA retrieves the root CA certificate and private key
func (d *DAO) GetRootCA() (*model.Certificate, []byte, error) {
	var caCert model.Certificate
	var caKeyPEM []byte
	err := d.db.QueryRow(`SELECT serial_number, common_name, ca_cert_pem, ca_key_pem FROM root_ca LIMIT 1`).Scan(&caCert.Id, &caCert.CommonName, &caCert.PEMCertificate, &caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	return &caCert, caKeyPEM, nil
}

func (d *DAO) DeleteIssuedCertificate(serialNumber int64) error {
	_, err := d.db.Exec(`DELETE FROM issued_certificates WHERE serial_number=?`, serialNumber)
	return err
}

// StoreIssuedCertificate stores an issued certificate's serial number and PEM format
func (d *DAO) StoreIssuedCertificate(certificate *model.Certificate) error {
	_, err := d.db.Exec(`
	INSERT INTO issued_certificates (serial_number, common_name, certificate_pem)
	VALUES (?, ?)`, certificate.Id, certificate.CommonName, certificate.PEMCertificate)
	return err
}

// GetIssuedCertificate retrieves an issued certificate by serial number
func (d *DAO) GetIssuedCertificate(serialNumber int64) (*model.Certificate, error) {
	var certificate model.Certificate
	err := d.db.QueryRow(`SELECT serial_number, common_name, certificate_pem FROM issued_certificates WHERE serial_number = ?`, serialNumber).Scan(&certificate.Id, &certificate.CommonName, &certificate.PEMCertificate)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

// GetIssuedCertificateByCommonName retrieves an issued certificate by common name
func (d *DAO) GetIssuedCertificateByCommonName(commonName string) (*model.Certificate, error) {
	var certificate model.Certificate
	err := d.db.QueryRow(`SELECT serial_number, common_name, certificate_pem FROM issued_certificates WHERE common_name = ?`, commonName).Scan(&certificate.Id, &certificate.CommonName, &certificate.PEMCertificate)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

// GetAllIssuedCertificates retrieves all issued certificates from the database.
func (d *DAO) GetAllIssuedCertificates() ([]model.Certificate, error) {
	// Prepare to collect all certificates
	var certs []model.Certificate

	// Query all issued certificates
	rows, err := d.db.Query(`SELECT serial_number, common_name, certificate_pem FROM issued_certificates`)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err = rows.Close()
		if err != nil {
			return
		}
	}(rows)

	// Iterate over the rows and collect each certificate
	for rows.Next() {
		var certificate model.Certificate
		if err = rows.Scan(&certificate.Id, &certificate.CommonName, &certificate.PEMCertificate); err != nil {
			return nil, err
		}
		certs = append(certs, certificate)
	}

	// Check if any rows were found
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return certs, nil
}

func (d *DAO) EraseAllTables() error {
	var err error
	tables := []string{
		"issued_certificates",
		"crls",
		"root_ca",
		// Add other tables here
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}

	for _, table := range tables {
		stmt, err := tx.Prepare("DELETE FROM " + table)
		if err != nil {
			err = tx.Rollback()
			if err != nil {
				return fmt.Errorf("failed to rollback transaction: %v", err)
			}
			return fmt.Errorf("failed to prepare delete for table %s: %v", table, err)
		}
		if _, err = stmt.Exec(); err != nil {
			err = stmt.Close()
			if err != nil {
				return fmt.Errorf("failed to close delete for table %s: %v", table, err)
			}
			err = tx.Rollback()
			if err != nil {
				return fmt.Errorf("failed to rollback transaction: %v", err)
			}
			return fmt.Errorf("failed to execute delete for table %s: %v", table, err)
		}
		err = stmt.Close()
		if err != nil {
			return fmt.Errorf("failed to close delete for table %s: %v", table, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// StoreCRL stores a PEM-encoded CRL using the associated certificate serial
func (d *DAO) StoreCRL(serialNumber int64, crlPEM []byte) error {
	_, err := d.db.Exec(`
	INSERT INTO crls (serial_number, crl_pem)
	VALUES (?, ?)`, serialNumber, crlPEM)
	return err
}

// GetCRL retrieves the CRL for a given certificate serial number
func (d *DAO) GetCRL(serialNumber int64) ([]byte, error) {
	var crlPEM []byte
	err := d.db.QueryRow(`
	SELECT crl_pem FROM crls WHERE serial_number = ?`, serialNumber).Scan(&crlPEM)
	if err != nil {
		return nil, err
	}
	return crlPEM, nil
}

// GetLatestCRL retrieves the CRL for a given certificate serial number
func (d *DAO) GetLatestCRL() ([]byte, error) {
	var crlPEM []byte
	err := d.db.QueryRow(`
	SELECT crl_pem FROM crls ORDER BY created_at DESC LIMIT 1`).Scan(&crlPEM)
	if err != nil {
		return nil, err
	}
	return crlPEM, nil
}
