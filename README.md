# IFSF DUKPT and ANSI X9.19 Retail MAC

Utility project to compute encrypted sensitive data (DE-127) and IFSF Retail MAC (DE-128) for IFSF ISO 8583 financial messages.

Formatting sensitive data in TLV format and hashing of the message for which MAC has to be computed are not in 
the scope of this project.
  
## Algorithm explanations and pseudo-code

- Java Triple DES DUKPT Library by Software Verde (**Andrew Groot and Josh Green**).  
  https://github.com/SoftwareVerde/java-dukpt 
- Message Authentication Code (MAC) algorithm (Mohammad).  
  https://medium.com/@mohammad2603/message-authentication-code-mac-algorithm-ea9edaf66b3c 
- Retail MAC Calculation in Java (Bharathi Subramanian).  
  https://bharathisubramanian.wordpress.com/2013/03/23/retail-mac-calculation-in-java/ 
- DUKPT Within a Point of Sale Environment: How Does It Work? ().  
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
