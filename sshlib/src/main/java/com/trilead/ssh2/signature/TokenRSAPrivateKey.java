
package com.trilead.ssh2.signature;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.PrivateKey;
import java.security.spec.RSAPublicKeySpec;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;


public class TokenRSAPrivateKey implements PrivateKey
{
  private long key_id;

  public TokenRSAPrivateKey (String s)
  {
    key_id = new BigInteger (s, 16).longValue();
  }

  public TokenRSAPrivateKey (long l)
  {
    key_id = l;
  }

  public long getKeyId()
  {
    return key_id;
  }

  private void writeObject (ObjectOutputStream stream) throws IOException
  {
    throw new IOException();
  }

  public void readObject (ObjectInputStream stream) throws IOException
  {
    throw new IOException();
  }

  public void readObjectNoData()     throws ObjectStreamException
  {
    throw new ObjectStreamException() {};
  }

  public String getAlgorithm()
  {
    return "TokenRSA";
  }

  public String getFormat()
  {
    return "None";
  }

  public byte[] getEncoded()
  {
    return new byte[0];
  }
}

