package amn;
// A Java program for a Server

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.Scanner;


public class Server {

    public boolean RegisterClient(String user, String pass , String publicKey) throws SQLException {
        String signedIn = "no";
        System.out.println("registering");
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        statement.executeUpdate("INSERT INTO clients " + "VALUES ('" + user + "' , '" + pass + "' , '"+publicKey+"' , '"+signedIn+"')");
        return true;
    }

    public boolean SignIn(String user, String pass) throws SQLException, IOException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statment = connection.createStatement();
        Scanner reader = new Scanner(System.in);
        String query = "SELECT * FROM passwords.clients Where Usernames = '" + user + "' AND Password = '" + pass + "' ";
        ResultSet resultSet = statment.executeQuery(query);
        if (resultSet.next()) {
            System.out.println("exist");
            return true;
        }
        System.out.println("Information not correct");
        return false;
    }
    public void changeSignedIn(String user ,String signedIn ) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        String query = "UPDATE clients set SignedIn='" + signedIn + "' " +
                "WHERE Usernames = '" + user + "' ;";
        statement.executeUpdate(query);
    }
    public boolean isSignedIn (String user) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        String query = "SELECT SignedIn FROM passwords.clients Where Usernames = '" + user + "' ";
        ResultSet resultSet = statement.executeQuery(query);
        if (resultSet.next()) {
            if(resultSet.getString(1).equals("yes")){
                return true;
            }
        }
        return false;
    }

    public String GetPass(String user) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statment = connection.createStatement();
        String query = "SELECT * FROM passwords.clients Where Usernames = '" + user + "' ";
        ResultSet resultSet = statment.executeQuery(query);
        ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
        int columnsNumber = resultSetMetaData.getColumnCount();
        if (resultSet.next()) {
            String columnValue = resultSet.getString(2);
            return columnValue;
        } else {
            System.out.println("Information not correct");
            return null;
        }
    }
    public String GetPublicKey(String user) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statment = connection.createStatement();
        String query = "SELECT * FROM passwords.clients Where Usernames = '" + user + "' ";
        ResultSet resultSet = statment.executeQuery(query);
        ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
        int columnsNumber = resultSetMetaData.getColumnCount();
        if (resultSet.next()) {
            String columnValue = resultSet.getString(3);
            return columnValue;
        } else {
            System.out.println("Information not correct");
            return null;
        }
    }

    public static void main(String[] args) throws IOException, SQLException {
        Server server = new Server();
        server.isSignedIn("yassar");
    }
}