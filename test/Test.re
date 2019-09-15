let runTests = () => {
  Alcotest.run("Morph_session Test", [Morph_sessionTest.testSuite()]);
};

runTests();