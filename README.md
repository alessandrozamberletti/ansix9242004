# IFSF Security Fields Processor

Compute security fields for IFSF Host-to-Host Interface financial transaction messages under ANSI X9.24 version 2004 and ANSI X9.24 2009 encryption schemes.  

IFSF Host-to-Host standard in an adaption of ISO 8583 mainly devised for fuel payment transactions, but also used in several other applications. 

Using this library, the following fields can be easily calculated and parsed:
- Personal Identification Number **DE-52**;
- Encrypted sensitive data **DE-127**;
- Message authentication code **DE-64**, **DE-128**.

To ease handling of field **DE-52**, utility methods to build and parse ISO 9564-1 Format 0 PIN blocks are also provided.

Formatting sensitive data in TLV format, hashing of the message for which ISO-9797-1 MAC has to be computed, and padding 
(using ether method 1 or method 2) are not in the scope of this library.

The library should only be used for testing purposes as it does not provide any sort of security.
  
## Algorithm explanations and pseudo-code

- Java Triple DES DUKPT Library by Software Verde (**Andrew Groot and Josh Green**).  
  https://github.com/SoftwareVerde/java-dukpt 
- Message Authentication Code (MAC) algorithm (Mohammad).  
  https://medium.com/@mohammad2603/message-authentication-code-mac-algorithm-ea9edaf66b3c 
- Retail MAC Calculation in Java (Bharathi Subramanian).  
  https://bharathisubramanian.wordpress.com/2013/03/23/retail-mac-calculation-in-java/ 
- DUKPT Within a Point of Sale Environment: How Does It Work? (Futurex).  
  https://www.futurex.com/blog/dukpt-in-point-of-sale-how-does-it-work 
- DUKPT Explained with examples (Arthur Van Der Merwe).  
  https://arthurvandermerwe.com/2015/05/30/dukpt-explained-with-examples/ 
- How to decrypt card data.  
  https://idtechproducts.com/technical-post/how-to-decrypt-credit-card-data-part-ii/ 
- "Key" to Secure Data - P2PE - Derived Unique Key Per Transaction (Andrew McKenna).  
  https://www.foregenix.com/blog/p2pe-derived-unique-key-per-transaction-dukpt 
- IFSF Recommended Security Standards v2.00.  

## Sources

- Java Triple DES DUKPT Library by Software Verde (authors: Andrew Groot and Josh Green).  
  https://github.com/SoftwareVerde/java-dukpt 
- Retail MAC Calculation in Java (Bharathi Subramanian).  
  https://bharathisubramanian.wordpress.com/2013/03/23/retail-mac-calculation-in-java/ 
