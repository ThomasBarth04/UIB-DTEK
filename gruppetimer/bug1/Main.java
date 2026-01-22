class Main {
  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.out.println("Usage: java Main <message>");
      return;
    }

    String command = "echo " + args[0];

    Process process = Runtime.getRuntime().exec(
        new String[] { "sh", "-c", command });

    process.getInputStream().transferTo(System.out);
    process.getErrorStream().transferTo(System.err);

    process.waitFor();
  }
}
