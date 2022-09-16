resource "aws_guardduty_detector" "MyDetector" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

#archiving/suppressing false positives
resource "aws_guardduty_filter" "Example" {
    action      = "ARCHIVE"
    detector_id = aws_guardduty_detector.primary.id
    name        = "Example_name"
    rank        = 1
    tags        = {}
    tags_all    = {}

    finding_criteria {
        criterion {
            equals     = [
                "false",
            ]
            field      = "service.archived"
        }
        criterion {
            equals     = [
                "i-0x0x0x0x0x", #instance_ID
            ]
            field      = "resource.instanceDetails.instanceId"
        }
        criterion {
            equals     = [
                "Execution:EC2/MaliciousFile", #refer to the findings types here:https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
            ]
            field      = "type"
        }

    }
    
}

