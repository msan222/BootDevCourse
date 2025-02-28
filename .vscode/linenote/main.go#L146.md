use sqlc generated database package to create new *database.Queries and store it in your apiConfig struct. 

- This will create an instance of the database.Queries struct, which contains methods for each query you've defined in your SQL files.