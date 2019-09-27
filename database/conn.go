package database

import (
	"database/sql"
	"fmt"
	"strings"

	crypt "github.com/wolvex/go/crypto"
	"github.com/wolvex/go/crypto/parser"
	//load mysql driver
	_ "github.com/go-sql-driver/mysql"
	//_ "github.com/lib/pq"
)

type DatabaseConnection interface {
	New(fn string) (*DbConnection, error)
	Open() (*sql.DB, error)
	Close()
	GetRows(rows *sql.Rows) (map[int]map[string]string, error)
	GetFirstRow() (string, error)
	Query(sqlStringName string, args ...interface{}) (*sql.Rows, error)
	Exec(sqlStringName string, args ...interface{}) (int64, error)
	Queryf(sqlStringName string, args ...interface{}) (*sql.Rows, error)
	Execf(sqlStringName string, args ...interface{}) (int64, error)
	InsertGetLastId(sqlStringName string, args ...interface{}) (int64, error)
}

//Config is global config for database connection
type DbConnection struct {
	Type     string            `yaml:"Type"`
	URL      string            `yaml:"URL"`
	Username string            `yaml:"Username"`
	Password string            `yaml:"Password"`
	Host     string            `yaml:"Host"`
	Schema   string            `yaml:"Schema"`
	SQL      map[string]string `yaml:"SQLCommand"`
	Db       *sql.DB
}

//var c.Db *sql.DB

func New(fn string) (*DbConnection, error) {
	var c DbConnection
	if err := parser.LoadYAML(&fn, &c); err != nil {
		return nil, err
	}

	if c.URL == "" {
		key := strings.Repeat(strings.ToUpper(c.Username), 2)
		if password, err := crypt.TripleDesDecrypt(c.Password, []byte(key), crypt.PKCS5UnPadding); err != nil {
			if encpass, e := crypt.TripleDesEncrypt(c.Password, []byte(key), crypt.PKCS5Padding); e == nil {
				//log.Debugf("Decryption error, try %s instead\n", encpass)
			}
			return nil, err
		} else {
			c.URL = fmt.Sprintf("%s:%s@(%s)/%s", c.Username, password, c.Host, c.Schema)
		}
	}

	return &c, nil
}

// OpenConnection prepares dbConnection for future connection to database
func (c DbConnection) Open() (*sql.DB, error) {
	c.Close()

	// Open database connection
	var err error
	//log.Debug("Initiating database connection ...")
	dbConn, err := sql.Open(c.Type, c.URL)
	if err != nil {
		return nil, err
	}

	dbConn.SetMaxOpenConns(100)

	err = dbConn.Ping()
	if err != nil {
		return nil, err
	}

	return dbConn, nil
}

// CloseConnection closes existing dbConnection
//
func (c DbConnection) Close() {
	if c.Db != nil {
		//log.Debug("Closing previous database connection.")
		c.Db.Close()
		c.Db = nil
	}
}

//ParsingRowsHelper parses recordset into map
func (c DbConnection) GetRows(rows *sql.Rows) (map[int]map[string]string, error) {
	var results map[int]map[string]string
	results = make(map[int]map[string]string)

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Make a slice for the values
	values := make([]sql.RawBytes, len(columns))

	// rows.Scan wants '[]interface{}' as an argument, so we must copy the
	// references into such a slice
	// See http://code.google.com/p/go-wiki/wiki/InterfaceSlice for details
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	// Fetch rows
	counter := 1
	for rows.Next() {
		// get RawBytes from data
		err = rows.Scan(scanArgs...)
		if err != nil {
			return nil, err
		}

		// initialize the second layer
		results[counter] = make(map[string]string)

		// Now do something with the data.
		// Here we just print each column as a string.
		var value string
		for i, col := range values {
			// Here we can check if the value is nil (NULL value)
			if col == nil {
				value = "NULL"
			} else {
				value = string(col)
			}
			results[counter][columns[i]] = value
		}
		counter++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

//ParsingRowsAndGetValue parse and gets column value in first record
func (c DbConnection) GetFirstRow(rows *sql.Rows, key string) (string, error) {
	results, err := c.GetRows(rows)
	if err != nil {
		return "", err
	}
	return results[1][key], nil
}

// Query sends SELECT command to database
func (c DbConnection) Query(sqlStringName string, args ...interface{}) (*sql.Rows, error) {
	// if no dbConnection, return
	//
	if c.Db == nil {
		return nil, fmt.Errorf("Database needs to be initiated first.")
	}

	var strSQL string
	var found bool

	//if strSQL, found = sqlCommandMap[sqlStringName]; !found {
	if strSQL, found = c.SQL[sqlStringName]; !found {
		strSQL = sqlStringName
	}

	rows, err := c.Db.Query(strSQL, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

//Exec executes UPDATE/INSERT/DELETE statements and returns rows affected
func (c DbConnection) Exec(sqlStringName string, args ...interface{}) (int64, error) {
	// if no dbConnection, return
	//
	if c.Db == nil {
		return 0, fmt.Errorf("Please OpenConnection prior Query")
	}

	var strSQL string
	var found bool

	//if strSQL, found = sqlCommandMap[sqlStringName]; !found {
	if strSQL, found = c.SQL[sqlStringName]; !found {
		strSQL = sqlStringName
	}

	// Execute the query
	res, err := c.Db.Exec(strSQL, args...)
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rows, nil
}

func (c DbConnection) InsertGetLastId(sqlStringName string, args ...interface{}) (int64, error) {
	// if no dbConnection, return
	//
	if c.Db == nil {
		return 0, fmt.Errorf("Please OpenConnection prior Query")
	}

	var strSQL string
	var found bool

	//if strSQL, found = sqlCommandMap[sqlStringName]; !found {
	if strSQL, found = c.SQL[sqlStringName]; !found {
		strSQL = sqlStringName
	}

	// Execute the query
	res, err := c.Db.Exec(strSQL, args...)
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}

	rows, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return rows, nil
}

func (c DbConnection) Queryf(sql string, a ...interface{}) (*sql.Rows, error) {
	return c.Query(fmt.Sprintf(sql, a...))
}

func (c DbConnection) Execf(sql string, a ...interface{}) (int64, error) {
	return c.Exec(fmt.Sprintf(sql, a...))
}
