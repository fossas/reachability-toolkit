use indoc::indoc;

pub fn get_example() -> &'static str {
    indoc! {"
        entries:
          - cve: 'CVE-2022-37865'                                 # ID of the CVE
            dependency_revision_id: 'mvn+org.apache.ivy:ivy'      # FOSSA locator: <ecosystem>+<package>$<version>
            function:                                             # Vulnerable Function
              kind: java                                          # Kind of function. Possible choices: 'java'.
              symbol: 'Class(ZipPacking)::ClassMethod(unpack)'    # Qualified Function Path. Possible choices: Class(), ClassMethod(), Constructor(). `::` denotes sub scope.
            researcher: 'Name of the person'                      # Name of the researcher
            notes: 'some notes'                                   # Any notes (Optional)    
    "}
}
