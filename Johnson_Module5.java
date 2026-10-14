//Kashana Johnson
/* Implementing hash tables
Collision handling techniques
Analyzing load factor and efficiency
Connecting hashing to cybersecurity concepts */
// 04/30/2026


import java.security.MessageDigest; //used to hash passwords securely
import java.security.NoSuchAlgorithmException; //handles hashing errors
import javax.swing.*; //GUI components like buttons, text fields, etc.
import java.awt.*; // layout and design tools

//main GUI application class that extends JFrame (window)
public class MainApp extends JFrame {
    
	private static final long serialVersionUID = 1L; //serialization ID for compatibility 

    private HashTable table = new HashTable(10); //create a hash table with initial capacity of 10
    
    //GUI input fields
    private JTextField keyField; //for username input
    private JPasswordField valueField; //for password input (hidden text)
    private JTextArea outputArea; //output display area for logs/messages
    private JLabel statusLabel; //shows size, load factor, and capacity

    // constructor: builds the GUI
    public MainApp() {
        setTitle("Secure Credential Vault"); //window title
        setSize(500, 450); //window size
        setLayout(new BorderLayout()); //layout manager

        //panel for input fields (username + password)
        JPanel inputPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        //initalize input fields
        keyField = new JTextField(); //plain text for username
        valueField = new JPasswordField(); //masked input for password
        
        //add labels and fields to panel
        inputPanel.add(new JLabel("Username (Key):"));
        inputPanel.add(keyField);
        inputPanel.add(new JLabel("Password (Value):"));
        inputPanel.add(valueField);

        JPanel btnPanel = new JPanel(); //button panel
        
        //buttons for operation
        JButton insertBtn = new JButton("Secure & Store"); //insert data
        JButton searchBtn = new JButton("Search Key"); //search for key
        JButton removeBtn = new JButton("Delete"); //remove key
        
        //add buttons to panel
        btnPanel.add(insertBtn);
        btnPanel.add(searchBtn);
        btnPanel.add(removeBtn);

        //top panel combines input + buttons
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(inputPanel, BorderLayout.CENTER);
        topPanel.add(btnPanel, BorderLayout.SOUTH);

        //output area for displaying actions/results
        outputArea = new JTextArea();
        outputArea.setEditable(false); //prevent user editing
        outputArea.setBackground(new Color(245, 245, 245)); //light gray background
        
        //shows table stats
        statusLabel = new JLabel(" Size: 0 | Load Factor: 0.0 | Capacity: 10");
        statusLabel.setBorder(BorderFactory.createEtchedBorder());

        //add components to main frame
        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(outputArea), BorderLayout.CENTER); //scrollable output
        add(statusLabel, BorderLayout.SOUTH);

        // --- INTERFACE LOGIC ---

        //INSERT BUTTON LOGIC
        insertBtn.addActionListener(_ -> {
            String key = keyField.getText(); //get username
            String value = new String(valueField.getPassword()); //get password
            
            //validate input
            if(!key.isEmpty() && !value.isEmpty()) {
                table.put(key, value); //store in hash table (hashed internally)
                updateDisplay("SECURE STORE: " + key + " (hashed in memory)");
                
                //clear fields after insert
                keyField.setText("");
                valueField.setText("");
            } else {
                updateDisplay("ERROR: Username or Password cannot be empty.");
            }
        });

        //SEARCH BUTTON LOGIC
        searchBtn.addActionListener(_ -> {
            String key = keyField.getText(); //get key
            
            if(!key.isEmpty()) {
                String result = table.get(key); //retrieve hashed password
                updateDisplay("SEARCH RESULT [" + key + "]: " + result);
            }
        });

        //DELETE BUTTON LOGIC
        removeBtn.addActionListener(_  -> {
            String key = keyField.getText(); //get key
            
            if(!key.isEmpty()) {
                table.remove(key); //remove entry
                updateDisplay("REMOVED: " + key);
            }
        });

        
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); //close app when window is closed 
        setLocationRelativeTo(null); //center window on screen
        setVisible(true); //make window visible
    }

    //updates output area and status label
    private void updateDisplay(String message) {
        outputArea.append(message + "\n"); //add message
        
        //update table stats
        statusLabel.setText(String.format(" Size: %d | Load Factor: %.2f | Table Capacity: %d", 
                            table.size(), table.getLoadFactor(), table.getCapacity()));
    }

    
    public static void main(String[] args) { //main method (entry point of program)
        SwingUtilities.invokeLater(() -> new MainApp()); //ensures GUI runs on correct thread
    }
}

// =========== HASH TABLE IMPLEMENTATION ==========
class HashTable {
    private Node[] table; //array of linked lists(chaining for collisions)
    private int size; //current number of elements
    private int capacity; //total capacity of table
    private static final double LOAD_FACTOR_THRESHOLD = 0.75; //load factor threshold before resizing

    //Constructor
    public HashTable(int capacity) {
        this.capacity = capacity; //set capacity
        this.table = new Node[capacity]; //create array
        this.size = 0; //start empty
    }

    //hash function: converts key into array index
    private int hash(String key) {
        return (key.hashCode() & 0x7fffffff) % capacity; //ensures positive number and compress into table size
    }

    //secure hashing using SHA-256
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256"); //create hasher
            byte[] hashBytes = md.digest(password.getBytes()); //convert password to hash
            StringBuilder hexString = new StringBuilder(); //store hex result
            
            //convert bytes into readable hex format
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                
                //ensure 2-digit format
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString(); //return hashed password
        } catch (NoSuchAlgorithmException e) {
            return "Critical Error: Hashing Algorithm Not Found";
        }
    }

    //INSERT METHOD
    public void put(String key, String value) {
        if (key == null || value == null) return; //prevent null input

        if ((double) (size + 1) / capacity >= LOAD_FACTOR_THRESHOLD) { //check load factor before inserting
            resize(); //expand table if too full
        }

        int index = hash(key); //compute index
        String secureValue = hashPassword(value); //hash password
        
        Node current = table[index];
        
        //traverse linked list to check for duplicate keys
        while (current != null) {
            if (current.key.equals(key)) {
                current.value = secureValue; //update existing value
                return;
            }
            current = current.next;
        }

        //insert new node at beginning (chaining)
        Node newNode = new Node(key, secureValue);
        newNode.next = table[index];
        table[index] = newNode;
        size++; //increase size
    }

    /* Once exposed, plain text passwords give hackers instant access to user accounts.
       Hashing ensures that even if the database is stolen, the actual passwords remain 
       numerically unclear, making unauthorized access significantly harder. */
    public String get(String key) {
        if (key == null) return "[Entry Not Found]";
        int index = hash(key); //find index
        Node current = table[index];
        
        //traverse linked list
        while (current != null) {
            if (current.key.equals(key)) return current.value;
            current = current.next;
        }
        return "[Entry Not Found]";
    }

    //REMOVE METHOD
    public void remove(String key) {
        if (key == null) return;
        int index = hash(key);
        Node current = table[index];
        Node prev = null;
        
        //traverse linked list
        while (current != null) {
            if (current.key.equals(key)) {
                if (prev == null) table[index] = current.next; //remove head
                else prev.next = current.next; //bypass node
                size--; //decrease size
                return;
            }
            prev = current;
            current = current.next;
        }
    }

    //returns number of stored elements
    public int size() {
        return this.size;
    }

    //resize table when load factor is too high
    private void resize() {
        int oldCapacity = capacity;
        Node[] oldTable = table;
        
        capacity *= 2; //double capacity
        table = new Node[capacity]; //new table
        size = 0; //reset size

        //reinsert all elements
        for (int i = 0; i < oldCapacity; i++) {
            Node current = oldTable[i];
            while (current != null) {
                putInternal(current.key, current.value);
                current = current.next;
            }
        }
    }

    //internal insert (no hashing again)
    private void putInternal(String key, String secureValue) {
        int index = hash(key);
        Node newNode = new Node(key, secureValue);
        newNode.next = table[index];
        table[index] = newNode;
        size++;
    }

    
    public double getLoadFactor() { return (double) size / capacity; } //returns load factor
    public int getCapacity() { return capacity; } //returns current capacity
}

//node class for linked list (chaining)
class Node {
    String key; //username
    String value; //hashed password
    Node next; //pointer to next node
    
    //constructor
    Node(String key, String value) {
        this.key = key;
        this.value = value;
    }
}