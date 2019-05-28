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

@Parameters(commandDescription = "Execute legacy tests")
public class EncryptionLegacyTest extends BaseCommand {

  @Parameter(names={"-p", "--path-to-encrypted-file"},
    description="path to encryped file")
  String parquetFilesDir = "target/tests/TestEncryption/";

  public EncryptionLegacyTest(Logger console) {
    super(console);
  }

  @Override
  public int run() throws IOException {

    String fileName = "tester";
    byte[] AADPrefix = fileName.getBytes(StandardCharsets.UTF_8);
    Path file = new Path(parquetFilesDir);

    ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), file).build();
    int i;
    for (i = 0; i < 500; i++) {
      Group group = null;
      group= reader.read();
      boolean expect = false;
      if ((i % 2) == 0)
        expect = true;
      // read two unencrypted columns
      boolean bool_res = group.getBoolean("boolean_field", 0);
      if (bool_res != expect)
        System.out.println("Wrong bool");
      int int_res = group.getInteger("int32_field", 0);
      if (int_res != i)
        System.out.println("Wrong int");
    }
    System.out.println("JAVA TEST i=" + i);
    reader.close();


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
