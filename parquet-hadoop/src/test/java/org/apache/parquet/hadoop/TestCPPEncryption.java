/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.parquet.hadoop;

import static org.junit.Assert.assertEquals;
import static org.apache.parquet.hadoop.TestUtils.enforceEmptyDir;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.junit.Rule;
import org.junit.Test;

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;

import org.apache.parquet.crypto.ColumnDecryptionProperties;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.crypto.StringKeyIdRetriever;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroupFactory;

import org.apache.parquet.crypto.keytools.WrappedKeyManager;
import org.apache.parquet.crypto.DecryptionKeyRetriever;
import org.apache.parquet.crypto.keytools.KmsClient;

import org.apache.hadoop.conf.Configuration;

import org.apache.parquet.hadoop.example.GroupReadSupport;
import org.apache.parquet.hadoop.metadata.ColumnPath;

import org.junit.rules.TemporaryFolder;

public class TestCPPEncryption {

  @Test
  public void test() throws Exception {
    byte[] FOOTER_ENCRYPTION_KEY = new String("0123456789012345").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY1 = new String("1234567890123450").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY2 = new String("1234567890123451").getBytes();

    StringKeyIdRetriever kr = new StringKeyIdRetriever();
    kr.putKey("kf", FOOTER_ENCRYPTION_KEY);
    kr.putKey("kc1", COLUMN_ENCRYPTION_KEY1);
    kr.putKey("kc2", COLUMN_ENCRYPTION_KEY2);

    Path file = new Path("/home/eres/parquet-encryption/cpp/arrow_repo/build/parquet_cpp_example.parquet.encrypted");
    FileDecryptionProperties decryptionProperties = FileDecryptionProperties.builder()
      .withKeyRetriever(kr)
      .build();

    ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), file).withDecryption(decryptionProperties).build();
    int i;
    for (i = 0; i < 500; i++) {
      Group group = null;
      group= reader.read();
      boolean expect = false;
      if ((i % 2) == 0)
        expect = true;
      assertEquals(expect, group.getBoolean("boolean_field", 0));
      assertEquals(i, group.getInteger("int32_field", 0),  0.001);
      float tmp1 = (float)i * 1.1f;
      assertEquals(tmp1, group.getFloat("float_field", 0),  0.001);
      double tmp = (i * 1.1111111);
      assertEquals(tmp, group.getDouble("double_field", 0), 0.001);
    }
    System.out.println("i=" + i);
    reader.close();
    //    enforceEmptyDir(conf, root);
  }


  @Rule
  public TemporaryFolder temp = new TemporaryFolder();
}


