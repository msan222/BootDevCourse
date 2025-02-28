sql.Open() doesn't immediately open a connectio, but instead returns a *sql.DB object, which you use to interact with the database

- takes a driver name (name of the database driver you are using), in this case it is postgres.

- takes a connection string (dataSourceName) that contains the necessary info for connecting to the database. 

Return Values: 
    - db - this is a pointer to a sql.DB object which represents the database connection pool. It manages a pool of connections that are reused. 