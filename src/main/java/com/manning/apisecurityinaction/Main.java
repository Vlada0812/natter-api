package com.manning.apisecurityinaction;

import java.nio.file.*;

import com.manning.apisecurityinaction.controller.*;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;
import spark.*;

import static spark.Spark.*;

public class Main {

    public static void main(String... args) throws Exception {
        
        //Intialize the database with priveleged user
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        //Switch to the natter_api_use and recreate the db objects
        datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter_api_user", "password");

        database = Database.forDataSource(datasource);
        var spaceController = new SpaceController(database);

        post("/spaces", spaceController::createSpace);

        after((request, response) -> {
            response.type("application/json");
        });
        // Remove the header containing the server type from the response
        afterAfter((request, response) ->
            response.header("Server", ""));

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString());
        notFound(new JSONObject()
            .put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest); 
        exception(JSONException.class, Main::badRequest);
        exception(EmptyResultException.class, 
            (e, request, response) -> response.status(404));

        // Remove protection against XSS attack to try to exploit
        afterAfter((request, response) -> {
            response.header("X-XSS-Protection", "0");
        });

    }

    private static void createTables(Database database) throws Exception {
        var path = Paths.get(
                Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        //remove the leak of the exception class details by using ex.geytMessage instead of just ex
        response.body("{\"error\": \"" + ex.getMessage() + "\"}");
    }
}