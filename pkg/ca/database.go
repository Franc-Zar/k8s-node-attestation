package ca

import (
	"database/sql"
	"fmt"
	"github.com/franc-zar/k8s-node-attestation/pkg/logger"
	_ "modernc.org/sqlite"
)

type DAO struct {
	db *sql.DB
}

// Close closes the database connection
func (d *DAO) Close() {
	err := d.db.Close()
	if err != nil {
		logger.Fatal("Failed to close attestation database: %v", err)
	}
}

// Open opens the database connection
func (d *DAO) Open(dataSourceName string) {
	var err error
	d.db, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		logger.Fatal("failed to open registrar db: %v", err)
	}
}

func (d *DAO) Init() {
	var err error
	// Table for issued certificates
	createIssuedCertsTableQuery := `
	CREATE TABLE IF NOT EXISTS issued_certificates (
		serial_number INTEGER PRIMARY KEY,
		certificate_pem TEXT NOT NULL,
		issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err = d.db.Exec(createIssuedCertsTableQuery); err != nil {
		logger.Fatal("failed to create issued_certificates table: %w", err)
	}

	// Table for revoked certs / CRL entries
	createCRLsTableQuery := `
	CREATE TABLE IF NOT EXISTS crls (
		cert_serial INTEGER PRIMARY KEY,
		crl_pem TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err = d.db.Exec(createCRLsTableQuery); err != nil {
		logger.Fatal("failed to create crls table: %w", err)
	}

	// Table for root CA material
	createRootCATableQuery := `
	CREATE TABLE IF NOT EXISTS root_ca (
		ca_cert_pem TEXT NOT NULL,
		ca_key_pem TEXT NOT NULL
	);`
	if _, err = d.db.Exec(createRootCATableQuery); err != nil {
		logger.Fatal("failed to create root_ca table: %w", err)
	}
}

// StoreRootCA stores the root CA material (certificate and private key)
func (d *DAO) StoreRootCA(caCertPEM, caKeyPEM []byte) error {
	_, err := d.db.Exec(`
	INSERT INTO root_ca (ca_cert_pem, ca_key_pem)
	VALUES (?, ?)`, caCertPEM, caKeyPEM)
	return err
}

// GetRootCA retrieves the root CA certificate and private key
func (d *DAO) GetRootCA() ([]byte, []byte, error) {
	var caCertPEM, caKeyPEM []byte
	err := d.db.QueryRow(`SELECT ca_cert_pem, ca_key_pem FROM root_ca LIMIT 1`).Scan(&caCertPEM, &caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	return caCertPEM, caKeyPEM, nil
}

func (d *DAO) DeleteIssuedCertificate(serialNumber int64) error {
	_, err := d.db.Exec(`DELETE FROM issued_certificates WHERE serial_number=?`, serialNumber)
	return err
}

// StoreIssuedCertificate stores an issued certificate's serial number and PEM format
func (d *DAO) StoreIssuedCertificate(serialNumber int64, certPEM []byte) error {
	_, err := d.db.Exec(`
	INSERT INTO issued_certificates (serial_number, certificate_pem)
	VALUES (?, ?)`, serialNumber, certPEM)
	return err
}

// GetIssuedCertificate retrieves an issued certificate by serial number
func (d *DAO) GetIssuedCertificate(serialNumber int64) ([]byte, error) {
	var certPEM []byte
	err := d.db.QueryRow(`SELECT certificate_pem FROM issued_certificates WHERE serial_number = ?`, serialNumber).Scan(&certPEM)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// GetAllIssuedCertificates retrieves all issued certificates from the database.
func (d *DAO) GetAllIssuedCertificates() ([][]byte, error) {
	// Prepare to collect all certificates
	var certs [][]byte

	// Query all issued certificates
	rows, err := d.db.Query(`SELECT certificate_pem FROM issued_certificates`)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err = rows.Close()
		if err != nil {
			logger.Fatal("failed to close issued_certificates table: %v", err)
		}
	}(rows)

	// Iterate over the rows and collect each certificate
	for rows.Next() {
		var certPEM []byte
		if err := rows.Scan(&certPEM); err != nil {
			return nil, err
		}
		certs = append(certs, certPEM)
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
		"revoked_certificates",
		"certificate_revocation_lists",
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
	INSERT INTO crls (cert_serial, crl_pem)
	VALUES (?, ?)`, serialNumber, crlPEM)
	return err
}

// GetCRL retrieves the CRL for a given certificate serial number
func (d *DAO) GetCRL(serialNumber int64) ([]byte, error) {
	var crlPEM []byte
	err := d.db.QueryRow(`
	SELECT crl_pem FROM crls WHERE cert_serial = ?`, serialNumber).Scan(&crlPEM)
	if err != nil {
		return nil, err
	}
	return crlPEM, nil
}

// GetCRL retrieves the CRL for a given certificate serial number
func (d *DAO) GetLatestCRL() ([]byte, error) {
	var crlPEM []byte
	err := d.db.QueryRow(`
	SELECT crl_pem FROM crls ORDER BY created_at DESC LIMIT 1`).Scan(&crlPEM)
	if err != nil {
		return nil, err
	}
	return crlPEM, nil
}
