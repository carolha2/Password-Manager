package amn;

import com.sun.xml.internal.bind.v2.runtime.Name;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class SignedIn {
    public static void Add(String name, String email, String password, String description, String files, String user) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        int id = 1;
        statement.executeUpdate("INSERT INTO accounts (Name , Email , Password , Description , Files , Usernames) " + "VALUES ('"+name+"' , '"+email+"' , '"+password+"' , '"+description+"' , '"+files+"' , '"+user+"')");
    }
    public void DeleteName(String username, String oldName) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statment = connection.createStatement();
        String query = "DELETE FROM accounts " +
                "WHERE accounts.Usernames = '" + username + "' AND accounts.Name = '" + oldName + "' ;";
        statment.executeUpdate(query);
    }

    public void EditName(String username, String oldName, String newName) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statment = connection.createStatement();
        String query = "UPDATE accounts set Name='" + newName + "' " +
                "WHERE accounts.Usernames = '" + username + "' AND accounts.Name = '" + oldName + "' ;";
        statment.executeUpdate(query);
    }

    public List<Message> SearchByName(String username, String name) throws SQLException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        String query = "SELECT accounts.* FROM accounts " +
                "INNER JOIN clients ON (accounts.Usernames=clients.Usernames) " +
                "WHERE accounts.Usernames = '" + username + "' AND accounts.Name = '" + name + "';";
        ResultSet resultSet = statement.executeQuery(query);
        ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
        int columnsNumber = resultSetMetaData.getColumnCount();
        List<Message> messages = new ArrayList<>();
        boolean flag = false;
        Encryption encryption = new Encryption();
        byte[] encryptKey= Files.readAllBytes(Paths.get("keys/symmetric"));
        while (resultSet.next()) {
            flag = true;
            for (int i = 1; i <= columnsNumber; i++) {
                if (i > 1) System.out.print(" ");
                String columnValue = resultSet.getString(i);
                if(columnValue == null){
                    columnValue = "null";
                }
                columnValue = encryption.encryptAES(columnValue,encryptKey);
                System.out.println(columnValue);
                messages.add(new Message(columnValue));
            }
        }
        if(!flag)
            messages.add(new Message(encryption.encryptAES("No info to display",encryptKey)));
        return messages;
        /*ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
        int columnsNumber = resultSetMetaData.getColumnCount();
        for (int i = 1; i <= columnsNumber; i++){
            if (i > 1) System.out.print("     ");
            System.out.print(resultSetMetaData.getColumnName(i));
        }
        while (resultSet.next()){
            System.out.println();
            for(int i = 1; i <= columnsNumber; i++){
                if (i > 1) System.out.print(" ");
                String columnValue = resultSet.getString(i);
                System.out.print(columnValue);
            }
        }
*/
    }


    public List<Message> GetAll(String username) throws SQLException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwords", "root", "mashroo3amn");
        Statement statement = connection.createStatement();
        String query = "SELECT accounts.* FROM accounts INNER JOIN clients ON (accounts.Usernames=clients.Usernames) WHERE accounts.Usernames = '" + username + "';";
        ResultSet resultSet = statement.executeQuery(query);
        ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
        int columnsNumber = resultSetMetaData.getColumnCount();
        /*for (int i = 1; i <= columnsNumber; i++){
            if (i > 1) System.out.print("     ");
            System.out.print(resultSetMetaData.getColumnName(i));
        }
        while (resultSet.next()){
            System.out.println();
            for(int i = 1; i <= columnsNumber; i++){
                if (i > 1) System.out.print(" ");
                String columnValue = resultSet.getString(i);
                System.out.print(columnValue);
            }
        }*/
        List<Message> messages = new ArrayList<>();
        boolean flag = false;
        Encryption encryption = new Encryption();
        byte[] encryptKey= Files.readAllBytes(Paths.get("keys/symmetric"));
        while (resultSet.next()) {
            flag = true;
            for (int i = 1; i <= columnsNumber; i++) {
                if (i > 1) System.out.print(" ");
                String columnValue = resultSet.getString(i);
                if(columnValue == null){
                    columnValue = "null";
                }
                columnValue = encryption.encryptAES(columnValue,encryptKey);
                System.out.println(columnValue);
                messages.add(new Message(columnValue));
            }
        }
        if(!flag)
            messages.add(new Message(encryption.encryptAES("No info to display",encryptKey)));
        return messages;

    }

    public static void main(String[] args) throws SQLException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
    }
}
