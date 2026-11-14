# frozen_string_literal: true

require "open3"

# Bouncy Castle, used for the interoperability tests (docs/design.md,
# chapter 9). `rake test:fetch_bouncy_castle` downloads the jars from Maven
# Central into DIR; interop/ErsInterop.java is run with them by the Java
# single-file launcher (a JDK is needed).
module BouncyCastle
  VERSION = "1.87"
  DIR = File.expand_path("../../interop/lib", __dir__)
  PROGRAM = File.expand_path("../../interop/ErsInterop.java", __dir__)

  # Artifact => SHA-256 of its jar.
  JARS = {
    "bcprov-jdk18on" => "12d2d3dd82a9ec15e92ec7c7943ee64f6097c6dc12c07e984f1693b77565b9aa",
    "bcutil-jdk18on" => "af46dd381553fdc466cd0c18f8bf2144c7dbcb7337eee3e16cab15e96613ddf0",
    "bcpkix-jdk18on" => "a44be2660d72ed88673372b8cc2d53a25a5aaf27122fb803ed93f07147536aa1",
  }.freeze

  module_function

  def file_name(artifact)
    "#{artifact}-#{VERSION}.jar"
  end

  def path(artifact)
    File.join(DIR, file_name(artifact))
  end

  def url(artifact)
    "https://repo1.maven.org/maven2/org/bouncycastle/#{artifact}/#{VERSION}/#{file_name(artifact)}"
  end

  def jars_available?
    JARS.each_key.all? { |artifact| File.file?(path(artifact)) }
  end

  def java_available?
    _, status = Open3.capture2e("java", "-version")
    status.success?
  rescue SystemCallError
    false
  end

  # Runs ErsInterop.java with args and returns its standard output. Raises
  # when it fails.
  def run(*args)
    classpath = JARS.each_key.map { path(_1) }.join(File::PATH_SEPARATOR)
    out, err, status = Open3.capture3("java", "-cp", classpath, PROGRAM, *args)
    raise "ErsInterop #{args.first} failed (#{status}):\n#{err}#{out}" unless status.success?

    out
  end
end
