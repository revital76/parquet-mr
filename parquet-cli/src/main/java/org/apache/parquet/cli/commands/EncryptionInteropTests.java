/* Licensed to the Apache Software Foundation (ASF) under one
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
package org.apache.parquet.cli.commands;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.collect.Lists;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.cli.BaseCommand;
import org.apache.parquet.crypto.ColumnEncryptionProperties;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.crypto.StringKeyIdRetriever;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroupFactory;
import org.apache.parquet.hadoop.ParquetReader;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.GroupReadSupport;
import org.apache.parquet.hadoop.example.GroupWriteSupport;
import org.apache.parquet.hadoop.metadata.ColumnPath;
import org.apache.parquet.io.api.Binary;
import org.apache.parquet.schema.MessageType;
import org.slf4j.Logger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.ArrayList;
import java.util.Iterator;


import static org.apache.parquet.hadoop.metadata.CompressionCodecName.UNCOMPRESSED;
import static org.apache.parquet.schema.MessageTypeParser.parseMessageType;

@Parameters(commandDescription = "Execute iterop tests")
public class EncryptionInteropTests extends BaseCommand {

  @Parameter(names={"-p", "--parquet-files-path"},
    description="path to parquet-files")
  String parquetFilesDir = "target/tests/TestEncryption/";

  @Parameter(names={"-w", "--write-parquet"},
    description="Execute write parquet tests")
  boolean writeParquet = false;

  @Parameter(names={"-r", "--read-parquet"},
    description="Execute read parquet tests")
  boolean readParquet = false;

  public EncryptionInteropTests(Logger console) {
    super(console);
  }

  @Override
  public int run() throws IOException {

    String fileName = "tester";
    byte[] AADPrefix = fileName.getBytes(StandardCharsets.UTF_8);
    Path root = new Path(parquetFilesDir);

    Configuration conf = new Configuration();
    byte[] FOOTER_ENCRYPTION_KEY = new String("0123456789012345").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY1 = new String("1234567890123450").getBytes();
    byte[] COLUMN_ENCRYPTION_KEY2 = new String("1234567890123451").getBytes();

    if (this.writeParquet) {
      int numberOfEncryptionModesForWrite = 4;
      FileEncryptionProperties[] encryptionPropertiesList = new FileEncryptionProperties[numberOfEncryptionModesForWrite];

      List<Integer> testsNumber = new ArrayList<Integer>();
      // #2 Encrypt two columns and the footer
      testsNumber.add(new Integer(2));
      ColumnEncryptionProperties columnProperties20 = ColumnEncryptionProperties
        .builder("double_field")
        .withKey(COLUMN_ENCRYPTION_KEY1)
        .withKeyID("kc1")
        .build();

      ColumnEncryptionProperties columnProperties21 = ColumnEncryptionProperties
        .builder("float_field")
        .withKey(COLUMN_ENCRYPTION_KEY2)
        .withKeyID("kc2")
        .build();

      String footerKeyName = "kf";

      byte[] footerKeyMetadata = footerKeyName.getBytes(StandardCharsets.UTF_8);
      Map<ColumnPath, ColumnEncryptionProperties> columnPropertiesMap2 = new HashMap<>();

      columnPropertiesMap2.put(columnProperties20.getPath(), columnProperties20);
      columnPropertiesMap2.put(columnProperties21.getPath(), columnProperties21);

      FileEncryptionProperties encryptionProperties = FileEncryptionProperties.builder(FOOTER_ENCRYPTION_KEY)
        .withFooterKeyMetadata(footerKeyMetadata)
        .withEncryptedColumns(columnPropertiesMap2)
        .build();

      encryptionPropertiesList[0] = encryptionProperties;

      testsNumber.add(new Integer(4));
      Map<ColumnPath, ColumnEncryptionProperties> columnPropertiesMap4 = new HashMap<>();
      ColumnEncryptionProperties columnProperties40 = ColumnEncryptionProperties
        .builder("double_field")
        .withKey(COLUMN_ENCRYPTION_KEY1)
        .withKeyID("kc1")
        .build();

      ColumnEncryptionProperties columnProperties41 = ColumnEncryptionProperties
        .builder("float_field")
        .withKey(COLUMN_ENCRYPTION_KEY2)
        .withKeyID("kc2")
        .build();
      columnPropertiesMap4.put(columnProperties40.getPath(), columnProperties40);
      columnPropertiesMap4.put(columnProperties41.getPath(), columnProperties41);
      encryptionProperties = FileEncryptionProperties.builder(FOOTER_ENCRYPTION_KEY)
        .withFooterKeyMetadata(footerKeyMetadata)
        .withEncryptedColumns(columnPropertiesMap4)
        .build();
      encryptionPropertiesList[1] = encryptionProperties;
      // #7 Encrypt two columns and the footer. Use AADPrefix.
      testsNumber.add(new Integer(7));

      Map<ColumnPath, ColumnEncryptionProperties> columnPropertiesMap7 = new HashMap<>();
      ColumnEncryptionProperties columnProperties70 = ColumnEncryptionProperties
        .builder("double_field")
        .withKey(COLUMN_ENCRYPTION_KEY1)
        .withKeyID("kc1")
        .build();

      ColumnEncryptionProperties columnProperties71 = ColumnEncryptionProperties
        .builder("float_field")
        .withKey(COLUMN_ENCRYPTION_KEY2)
        .withKeyID("kc2")
        .build();
      columnPropertiesMap7.put(columnProperties70.getPath(), columnProperties70);
      columnPropertiesMap7.put(columnProperties71.getPath(), columnProperties71);

      encryptionProperties = FileEncryptionProperties.builder(FOOTER_ENCRYPTION_KEY)
        .withFooterKeyMetadata(footerKeyMetadata)
        .withEncryptedColumns(columnPropertiesMap7)
        .withAADPrefix(AADPrefix)
        .build();

      encryptionPropertiesList[2] = encryptionProperties;

      MessageType schema = parseMessageType(
        "message test { "
          + "required boolean boolean_field; "
          + "required int32 int32_field; "
          + "required float float_field; "
          + "required double double_field; "
          + "} ");

      GroupWriteSupport.setSchema(schema, conf);
      SimpleGroupFactory f = new SimpleGroupFactory(schema);

      Iterator iter = testsNumber.iterator();
      int index = 0;
      while (iter.hasNext()) {
        Integer testNumber = (Integer)iter.next();
        System.out.println("\nWRITE TEST " + testNumber.toString());

        Path file = new Path(root, fileName + testNumber.toString() + ".parquet.encrypted");
        ParquetWriter<Group> writer = new ParquetWriter<Group>(
          file,
          new GroupWriteSupport(),
          UNCOMPRESSED, 1024, 1024, 512, true, false, ParquetWriter.DEFAULT_WRITER_VERSION, conf,
          encryptionPropertiesList[index]);
        index++;
        for (int i = 0; i < 100; i++) {
          boolean expect = false;
          if ((i % 2) == 0)
            expect = true;
          float float_val = (float) i * 1.1f;
          double double_val = (i * 1.1111111);
          writer.write(
            f.newGroup()
              .append("boolean_field", expect)
              .append("int32_field", i)
              .append("float_field", float_val)
              .append("double_field", double_val));
        }
        writer.close();
      }
    }
    if (this.readParquet) {
      int numberOfEncryptionModesForRead = 10;
      FileDecryptionProperties[] decryptionPropertiesList = new FileDecryptionProperties[numberOfEncryptionModesForRead];

      List<Integer> testsNumber = new ArrayList<Integer>();
      // #1 Decrypt two columns and the footer
      testsNumber.add(new Integer(1));

      StringKeyIdRetriever kr1 = new StringKeyIdRetriever();
      kr1.putKey("kf", FOOTER_ENCRYPTION_KEY);
      kr1.putKey("kc1", COLUMN_ENCRYPTION_KEY1);
      kr1.putKey("kc2", COLUMN_ENCRYPTION_KEY2);

      FileDecryptionProperties decryptionProperties = FileDecryptionProperties.builder()
        .withKeyRetriever(kr1)
        .build();

      int numTests = 0;
      decryptionPropertiesList[numTests++] = decryptionProperties;

      // #3 decrypt two columns and the footer without providing key for one column
      testsNumber.add(new Integer(3));

      StringKeyIdRetriever kr3 = new StringKeyIdRetriever();
      kr3.putKey("kf", FOOTER_ENCRYPTION_KEY);
      kr3.putKey("kc1", COLUMN_ENCRYPTION_KEY1);
      decryptionProperties = FileDecryptionProperties.builder()
        .withKeyRetriever(kr3)
        .build();

      decryptionPropertiesList[numTests++] = decryptionProperties;

      // #6 decrypt two columns and the footer. The files encrypted with AADPrefix
      testsNumber.add(new Integer(6));

      decryptionProperties = FileDecryptionProperties.builder()
        .withKeyRetriever(kr1) //re-use KeyRetriever
        .build();

      decryptionPropertiesList[numTests++] = decryptionProperties;

      // #8 decrypt two columns and the footer. The files encrypted with AADPrefix
      // and No AAD storing
      testsNumber.add(new Integer(8));
      decryptionProperties = FileDecryptionProperties.builder()
        .withKeyRetriever(kr1) //re-use KeyRetriever
        .withAADPrefix(AADPrefix)
        .build();
      decryptionPropertiesList[numTests++] = decryptionProperties;

      // #10 decrypt two columns and the footer. The files encrypted with gcm_ctr
      // algorithm
      testsNumber.add(new Integer(10));
      decryptionProperties = FileDecryptionProperties.builder()
        .withKeyRetriever(kr1) //re-use KeyRetriever
        .build();
      decryptionPropertiesList[numTests++] = decryptionProperties;

      Iterator iter = testsNumber.iterator();
      int index = 0;
      while (iter.hasNext()) {
        Integer testNumber = (Integer)iter.next();
        System.out.println("\nREAD TEST " + testNumber.toString());

        Path file = new Path(root, fileName + testNumber.toString() + ".parquet.encrypted");
        System.out.println("\nREAD TEST " + file.toString() + "index " + index);

        FileDecryptionProperties fileDecryptionProperties = decryptionPropertiesList[index];
        index++;
        ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), file).withDecryption(fileDecryptionProperties).withConf(conf).build();
        try {

          for (int i = 0; i < 500; i++) {
            Group group = null;
            group = reader.read();
            boolean expect = false;
            if ((i % 2) == 0)
              expect = true;
            boolean bool_res = group.getBoolean("boolean_field", 0);
            if (bool_res != expect)
              System.out.println("Wrong bool");
            int int_res = group.getInteger("int32_field", 0);
            if (int_res != i)
              System.out.println("Wrong int");
            float float_res = group.getFloat("float_field", 0);
            float tmp1 = (float) i * 1.1f;
            if (float_res != tmp1) System.out.println("Wrong float");

            double double_res = group.getDouble("double_field", 0);
            double tmp = (i * 1.1111111);
            if (double_res != tmp)
              System.out.println("Wrong double");
          }
        } catch (Exception e) {
          e.printStackTrace();
        }
        reader.close();

      }

    }
    return 0;
  }

  @Override
  public List<String> getExamples() {
    return Lists.newArrayList(
      "# Show the first 10 records in file \"data.avro\":",
      "data.avro",
      "# Show the first 50 records in file \"data.parquet\":",
      "data.parquet -n 50"
    );
  }
}
