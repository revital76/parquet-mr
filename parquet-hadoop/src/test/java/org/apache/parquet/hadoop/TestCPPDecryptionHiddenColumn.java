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

import static org.apache.parquet.hadoop.metadata.CompressionCodecName.UNCOMPRESSED;
import static org.apache.parquet.schema.MessageTypeParser.parseMessageType;
import org.apache.parquet.schema.MessageType;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import java.nio.charset.StandardCharsets;
import org.junit.Rule;
import org.junit.Test;

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;

import org.apache.parquet.hadoop.example.GroupReadSupport;

import org.apache.parquet.hadoop.example.GroupWriteSupport;
import org.apache.parquet.crypto.ColumnEncryptionProperties;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.crypto.StringKeyIdRetriever;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroupFactory;

import org.apache.parquet.crypto.keytools.WrappedKeyManager;
import org.apache.parquet.crypto.keytools.KmsClient;

import org.apache.hadoop.conf.Configuration;

import org.apache.parquet.hadoop.example.GroupReadSupport;
import org.apache.parquet.hadoop.metadata.ColumnPath;

import org.junit.rules.TemporaryFolder;

public class TestCPPDecryptionHiddenColumn {

  @Test
  public void test() throws Exception {
    Configuration conf = new Configuration();
    Path file = new Path("/home/eres//parquet_java.parquet.encrypted");

    byte[] FOOTER_ENCRYPTION_KEY = new String("0123456789012345").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY1 = new String("1234567890123450").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY2 = new String("1234567890123451").getBytes();


    Map<ColumnPath, ColumnEncryptionProperties> columnEnMap = new HashMap<>();
    ColumnEncryptionProperties columnEncryptionProps0 = ColumnEncryptionProperties
      .builder("double_field")
      .withKey(COLUMN_ENCRYPTION_KEY1)
      .withKeyID("kc1")
      .build();

    ColumnEncryptionProperties columnEncryptionProps1 = ColumnEncryptionProperties
      .builder("float_field")
      .withKey(COLUMN_ENCRYPTION_KEY2)
      .withKeyID("kc2")
      .build();

    String footerKeyName = "kf";

    byte[] footerKeyMetadata = footerKeyName.getBytes(StandardCharsets.UTF_8);

    columnEnMap.put(columnEncryptionProps0.getPath(), columnEncryptionProps0);
    columnEnMap.put(columnEncryptionProps1.getPath(), columnEncryptionProps1);

    FileEncryptionProperties encryptionProperties = FileEncryptionProperties.builder(FOOTER_ENCRYPTION_KEY)
      .withFooterKeyMetadata(footerKeyMetadata)
      .withEncryptedColumns(columnEnMap)
      .build();

    MessageType schema = parseMessageType(
      "message test { "
        + "required boolean boolean_field; "
        + "required int32 int32_field; "
        + "required float float_field; "
        + "required double double_field; "
        + "} ");

    GroupWriteSupport.setSchema(schema, conf);

    SimpleGroupFactory f = new SimpleGroupFactory(schema);

    ParquetWriter<Group> writer = new ParquetWriter<Group>(file,
      new GroupWriteSupport(),
      UNCOMPRESSED, 1024, 1024, 512, true, false,
      ParquetWriter.DEFAULT_WRITER_VERSION, conf,
      encryptionProperties);
    for (int i = 0; i < 100; i++) {
      boolean expect = false;
      if ((i % 2) == 0)
        expect = true;
      float tmp1 = (float)i * 1.1f;
      double tmp = (i * 1.1111111);
      writer.write(
        f.newGroup()
          .append("boolean_field", expect)
          .append("int32_field", i)
          .append("float_field", tmp1)
          .append("double_field", tmp));
    }
    writer.close();
    //    enforceEmptyDir(conf, root);
  }


  @Rule
  public TemporaryFolder temp = new TemporaryFolder();
}


