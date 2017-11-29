import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.zip.CRC32;
import javax.crypto.*;

public class FileTransfer {
    public static void main(String[] args) throws Exception {
        Scanner scan = new Scanner(System.in);
        if(args[0].equals("makekeys")) {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(4096);
                KeyPair keyPair = gen.genKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();
                try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
                    oos.writeObject(publicKey);
                }
                try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                    oos.writeObject(privateKey);
                }
            } catch(Exception e) {
                e.printStackTrace(System.err);
            }
        } else if(args[0].equals("server")) {
            PrivateKey privateKey = (PrivateKey)new ObjectInputStream(new FileInputStream(new File(args[1]))).readObject();
            int sPort = Integer.parseInt(args[2]);
            try(ServerSocket serverSocket = new ServerSocket(sPort)) {
                while(true) {
                    try {
                        Socket socket = serverSocket.accept();
                        Runnable server = () -> {
                            try {
                                String address = socket.getInetAddress().getHostAddress();
                                InputStream fromClient = socket.getInputStream();
                                ObjectInputStream objectFromClient = new ObjectInputStream(fromClient);
                                OutputStream toClient = socket.getOutputStream();
                                ObjectOutputStream objectToClient = new ObjectOutputStream(toClient);
                                Cipher cipher = null;
                                SecretKey key = null;
                                ByteBuffer buffer = null;
                                Message message = null;
                                byte[] data = null;
                                int sequence = 0;
                                int total = 0;
                                int size = 0;
                                CRC32 crc = new CRC32();
                                do {
                                    message = (Message) objectFromClient.readObject();
                                    if(message.getType().equals(MessageType.DISCONNECT)) {
                                        System.out.printf("Client disconnected: %s%n", address);
                                        socket.close();
                                        break;
                                    } else if(message.getType().equals(MessageType.START)) {
                                        StartMessage startMessage = (StartMessage)message;
                                        cipher = Cipher.getInstance("RSA");
                                        cipher.init(Cipher.UNWRAP_MODE, privateKey);
                                        key = (SecretKey) cipher.unwrap(startMessage.getEncryptedKey(), "AES",Cipher.SECRET_KEY);
                                        total = (int)startMessage.getSize() % startMessage.getChunkSize() > 0 ? (int)startMessage.getSize() / startMessage.getChunkSize() + 1 : size / startMessage.getChunkSize();
                                        size = (int)startMessage.getChunkSize() * total;
                                        data = new byte[size];
                                        buffer = ByteBuffer.wrap(data);
                                        objectToClient.writeObject(new AckMessage(sequence));
                                    } else if(message.getType().equals(MessageType.STOP)) {
                                        StopMessage stopMessage = (StopMessage)message;
                                        try {
                                            File file = new File(stopMessage.getFile());
                                            FileOutputStream writeToFile = new FileOutputStream(file);
                                            writeToFile.write(buffer.array());
                                            writeToFile.close();
                                            System.out.println("Transfer complete.");
                                            System.out.println("Output path: " + stopMessage.getFile());
                                        }
                                        catch(Exception e) {
                                            e.printStackTrace();
                                        }
                                        objectToClient.writeObject(new AckMessage(-1));
                                    } else if(message.getType().equals(MessageType.CHUNK)) {
                                        Chunk chunk = (Chunk)message;
                                        if(chunk.getSeq() == sequence) {                                                
                                            cipher = Cipher.getInstance("AES");
                                            cipher.init(Cipher.DECRYPT_MODE, key);
                                            byte[] chunkData = cipher.doFinal(chunk.getData());
                                            buffer.put(chunkData);
                                            crc.update(chunkData);
                                            int crcData = (int)crc.getValue();
                                            if(crcData == chunk.getCrc()) {
                                                sequence++;
                                                objectToClient.writeObject(new AckMessage(sequence));
                                                System.out.printf("Chunk received [%d/%d]\n", sequence, total);
                                            }   
                                        }
                                        else{
                                            objectToClient.writeObject(new AckMessage(sequence));
                                        }
                                    }
                                } while(true);
                                objectToClient.close();
                                objectFromClient.close();   
                            } catch(Exception e) {
                                e.printStackTrace();
                            }
                        };
                        Thread thread = new Thread(server);
                        thread.start();
                    } catch(Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch(Exception e) {
                e.printStackTrace();
            }
        } else if(args[0].equals("client")) {
            PublicKey publicKey = (PublicKey)new ObjectInputStream(new FileInputStream(new File(args[1]))).readObject();
            String host = args[2];
            int port = Integer.parseInt(args[3]);
            try(Socket socket = new Socket(host, port)) {
                OutputStream toServer = socket.getOutputStream();
                ObjectOutputStream objectToServer = new ObjectOutputStream(toServer);
                InputStream fromServer = socket.getInputStream();
                ObjectInputStream objectFromServer = new ObjectInputStream(fromServer);
                System.out.println("Connected to server: " + socket.getInetAddress().toString());
                KeyGenerator gen = KeyGenerator.getInstance("AES");
                gen.init(128);
                SecretKey sessionKey = gen.generateKey();
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.WRAP_MODE, publicKey);
                byte[] encryptedKey = cipher.wrap(sessionKey);
                System.out.print("Enter path: ");
                String path = scan.nextLine();
                path = path + ".txt";
                File file = new File(path);
                CRC32 crc = new CRC32();
                if(file.exists()) {
                    System.out.print("Enter chunk size [1024]: ");
                    int size = scan.nextInt();
                    int total = (int)file.length() / size;
                    StartMessage startMessage = new StartMessage(path, encryptedKey, size);
                    objectToServer.writeObject(startMessage);
                    AckMessage ackMessage = (AckMessage)objectFromServer.readObject();
                    FileInputStream content = new FileInputStream(file);
                    if((int)file.length() % size != 0) {
                        total++;
                    }
                    System.out.println("Sending: " + path + " File Size: " + file.length());
                    System.out.printf("Sending %d chunks.\n", total);
                    do {
                        if(ackMessage.getSeq() != -1) {
                            byte[] data = new byte[size];
                            content.read(data);
                            cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                            byte[] encryptedData = cipher.doFinal(data);
                            crc.update(data);
                            int crcData = (int)crc.getValue();
                            Chunk chunk = new Chunk(ackMessage.getSeq(), encryptedData, crcData);
                            objectToServer.writeObject(chunk);
                            int counter = ackMessage.getSeq()+1;
                            System.out.printf("Chunks completed [%d/%d]\n", counter, total);
                            ackMessage = (AckMessage) objectFromServer.readObject();
                        }   
                    } while(ackMessage.getSeq() < total);
                    objectToServer.writeObject(new StopMessage("test2.txt"));
                    objectToServer.writeObject(new DisconnectMessage());
                    objectFromServer.close();
                    objectToServer.close();
                    content.close();
                }
            }
        } else {
            System.out.println("Incorrect input!");
        }
    }
}
