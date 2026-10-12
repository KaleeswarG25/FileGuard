rule FileGuard_EICAR_Test_String {
 meta:
  description = "Detects standard EICAR antivirus test string; test use only"
  severity = "test"
 strings:
  $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
 condition:
  $eicar
}
