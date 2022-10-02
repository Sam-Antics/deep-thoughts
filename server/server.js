const express = require("express");
// import Apollo server
const { ApolloServer } = require("apollo-server-express");

// import typeDefs and resolvers
const { typeDefs, resolvers } = require("./schemas");
const db = require("./config/connection");

const PORT = process.env.PORT || 3002;
// create a new Apollo server and pass in our schema data
const server = new ApolloServer({
  typeDefs,
  resolvers,
});

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Create a new instance of an Apollo server with the GraphQL schema
const startApolloServer = async (typeDefs, resolvers) => {
  await server.start();
  // integrate Apollo server with the Express application as middleware
  server.applyMiddleware({ app });

  db.once("open", () => {
    app.listen(PORT, () => {
      console.log(`(👉ﾟヮﾟ)👉 API server running on port ${PORT}!`);
      // log where we can go to test the GQL API
      console.log(
        `Use GraphQL 📈 http://localhost:${PORT}${server.graphqlPath}`
      );
    });
  });
};

// call the async function to start the server
startApolloServer(typeDefs, resolvers);
