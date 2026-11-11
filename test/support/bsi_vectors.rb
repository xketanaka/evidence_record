# frozen_string_literal: true

# Evidence Record test vectors published by BSI (TR-ESOR / ERS test tool,
# 2017-03-16), as distributed in bcgit/bc-test-data.
#
# They are not bundled with this repository because their license is not
# stated anywhere (see docs/design.md, chapter 9). `rake test:fetch_vectors`
# downloads them into DIR; tests that need them are skipped when absent.
module BSIVectors
  REPOSITORY = "bcgit/bc-test-data"
  COMMIT = "554cb4fab4dd9ace4a4ca4e6574364440b8c8eef"
  REMOTE_DIR = "tsp/20170316_Testdaten"
  DIR = File.expand_path("../fixtures/bsi", __dir__)

  # Relative path => SHA-256 of the file at COMMIT.
  FILES = {
    "BSI TR-ESOR C.2 TestData/BIN.bin" => "a1d4e7b50d9693f9a31b2e9484ea6adfa585837730fe2ba94d13a5d4c81c32df",
    "BSI TR-ESOR C.2 TestData/ER_NOK_CHAIN.ers" => "0b1102ae8055eef9ddc2b6f78817e8183340353ab734912945af251eb36b3a1a",
    "BSI TR-ESOR C.2 TestData/ER_NOK_INIT.ers" => "0d322520f0212ecb07a349275648a83f76558a48b4ee7fce92d40011df606c58",
    "BSI TR-ESOR C.2 TestData/ER_NOK_SEQ.ers" => "d131df08a9f7bd904e2b71d5b3f2473dfd233eea195e9320093feb732e88e764",
    "BSI TR-ESOR C.2 TestData/ER_OK_CHAIN.ers" => "d37de16229e4ddf01ac57fe3bf2d173ab1df4c936a3a6429350b0fa7465222ee",
    "BSI TR-ESOR C.2 TestData/ER_OK_INIT.ers" => "3e8a59286f1f36f2faa4c370e73132be6dbb9ace74b873bfb92c441fed92c536",
    "BSI TR-ESOR C.2 TestData/ER_OK_SEQ.ers" => "85a90c6f030be8425de545d9bee3375294fbc54545669bcd9dea0d4a0bef4dce",
    "Testdaten_ERS-Testool/ReadMe.txt" => "404adbe4ff44600a5e3feb5730c3ae4dd0ae2ba21bd0962d4635d216c1b1e4e5",
    "Testdaten_ERS-Testool/rfc4998/1Chain1ATS/BIN.bin" => "a1d4e7b50d9693f9a31b2e9484ea6adfa585837730fe2ba94d13a5d4c81c32df",
    "Testdaten_ERS-Testool/rfc4998/1Chain1ATS/BIN_ER.ers" => "7b639924fbd4a19a6b1c3ff823ecbaed2b6e5263207761ef7907bb8f7550d0a5",
    "Testdaten_ERS-Testool/rfc4998/1Chain2ATS/BIN.bin" => "a1d4e7b50d9693f9a31b2e9484ea6adfa585837730fe2ba94d13a5d4c81c32df",
    "Testdaten_ERS-Testool/rfc4998/1Chain2ATS/BIN_ER.ers" => "e60c9e2adb6a02c6179803a37ff86997229732846390d1f308683b55ee244156",
    "Testdaten_ERS-Testool/rfc4998/1Chain2ATS/testRenewal.ers" => "a170d3c85ee16e648ad76ae05e04f8c74ff1dbd92cada45895d31f93174c6fa7",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN.bin" => "a1d4e7b50d9693f9a31b2e9484ea6adfa585837730fe2ba94d13a5d4c81c32df",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers" => "b9f833cc6e56c0684261fe96e1a0348531524b93f36a7a08309ffe86da85e27b",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers.0.0.tsr" => "26ab6e2414f4bea636036aa827921534893bb7226296ecefa2c3050db8c20ed6",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers.0.1.tsr" => "782ec5ed9b0d00a69cd1727fe4e134b5a16fc2b7b52bcf26ee6121f6c67bf653",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers.1.0.tsr" => "142c94afbc2d87a0424690ae2605cd03e520710c38d29145578f6407f28a090c",
    "Testdaten_ERS-Testool/rfc4998/2Chains3ATS/test.txt" => "ec654fac9599f62e79e2706abef23dfb7c07c08185aa86db4d8695f0b718d1b3",
  }.freeze

  module_function

  def path(relative)
    File.join(DIR, relative)
  end

  def available?
    FILES.each_key.all? { |relative| File.file?(path(relative)) }
  end

  def read(relative)
    File.binread(path(relative))
  end

  def url(relative)
    encoded = "#{REMOTE_DIR}/#{relative}".split("/").map { |s| s.gsub(" ", "%20") }.join("/")
    "https://raw.githubusercontent.com/#{REPOSITORY}/#{COMMIT}/#{encoded}"
  end
end
