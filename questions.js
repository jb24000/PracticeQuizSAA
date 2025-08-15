// AWS SAA-C03 Question Bank - 500 Questions
// Domain Distribution per Official Exam Guide:
// - Domain 1: Design Secure Architectures (30% = 150 questions)
// - Domain 2: Design Resilient Architectures (26% = 130 questions)
// - Domain 3: Design High-Performing Architectures (24% = 120 questions)
// - Domain 4: Design Cost-Optimized Architectures (20% = 100 questions)

const questionBank = {
    // Domain 1: Design Secure Architectures (150 questions - 30%)
    security: [
        {
            id: 'sec_001',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A financial services company is migrating their on-premises banking application to AWS. The application handles sensitive customer data and must comply with PCI DSS requirements. They need to ensure all data is encrypted at rest and in transit, with customer-managed encryption keys.",
            question: "Which combination of AWS services provides the MOST secure solution for managing encryption keys while maintaining compliance?",
            options: [
                "AWS KMS with customer-managed keys (CMK) and automatic key rotation enabled",
                "AWS CloudHSM cluster with custom key management application",
                "AWS Secrets Manager with automatic rotation and KMS encryption",
                "AWS Systems Manager Parameter Store with SecureString parameters"
            ],
            correct: 1,
            explanation: {
                correct: "CloudHSM provides FIPS 140-2 Level 3 validated hardware security modules, giving customers complete control over encryption keys, which is often required for strict financial compliance.",
                whyWrong: {
                    0: "While KMS is suitable for most scenarios, some financial regulations require hardware-based key storage that only CloudHSM provides",
                    2: "Secrets Manager is for credentials and API keys, not for data encryption key management",
                    3: "Parameter Store is for configuration data, not suitable for encryption key management in PCI DSS scenarios"
                },
                examStrategy: "For financial/healthcare compliance requiring FIPS 140-2 Level 3, choose CloudHSM. For general encryption needs, KMS is sufficient."
            }
        },
        {
            id: 'sec_002',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A multi-national corporation has workloads in multiple AWS accounts across different regions. They need to implement a centralized security monitoring solution that can detect threats, compliance violations, and automatically remediate security issues across all accounts.",
            question: "Which solution provides the MOST comprehensive security monitoring and automated remediation capabilities?",
            options: [
                "Enable AWS Security Hub in all accounts with AWS Config rules and Systems Manager automation documents for remediation",
                "Deploy Amazon GuardDuty with AWS Organizations integration and Lambda functions for automated responses",
                "Implement AWS CloudTrail with CloudWatch Events and Step Functions for security orchestration",
                "Use Amazon Detective with AWS Control Tower guardrails and Service Control Policies"
            ],
            correct: 0,
            explanation: {
                correct: "Security Hub provides centralized security findings from multiple services, Config rules detect compliance violations, and Systems Manager automation enables automated remediation across accounts.",
                whyWrong: {
                    1: "GuardDuty focuses on threat detection but lacks compliance checking capabilities that Security Hub provides",
                    2: "CloudTrail provides logging but doesn't offer built-in threat detection or compliance monitoring",
                    3: "Detective is for security investigation after incidents, not proactive monitoring and remediation"
                },
                examStrategy: "Security Hub is the central security service that aggregates findings from GuardDuty, Inspector, Macie, and others. It's the go-to for centralized security."
            }
        },
        {
            id: 'sec_003',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A healthcare organization stores patient records in S3 buckets. They need to ensure that sensitive data like Social Security Numbers and medical record numbers are automatically discovered and protected across all their S3 buckets.",
            question: "Which AWS service should be implemented to automatically discover and protect sensitive patient data?",
            options: [
                "Amazon Macie with custom data identifiers for healthcare data patterns",
                "AWS CloudTrail with S3 data events and CloudWatch alarms",
                "Amazon GuardDuty with S3 protection enabled",
                "AWS Config with custom rules for S3 bucket scanning"
            ],
            correct: 0,
            explanation: {
                correct: "Amazon Macie uses machine learning to automatically discover, classify, and protect sensitive data in S3, including PII and PHI with custom identifiers for healthcare-specific patterns.",
                whyWrong: {
                    1: "CloudTrail logs API calls but doesn't scan or classify data content",
                    2: "GuardDuty detects threats and unusual API patterns, not sensitive data discovery",
                    3: "Config evaluates resource configurations, not data content within S3 objects"
                },
                examStrategy: "Macie = sensitive data discovery in S3. GuardDuty = threat detection. CloudTrail = API logging. Config = resource compliance."
            }
        },
        {
            id: 'sec_004',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A startup wants to ensure their EC2 instances can securely access S3 buckets without storing AWS credentials on the instances.",
            question: "What is the MOST secure way to provide EC2 instances with access to S3 buckets?",
            options: [
                "Store AWS access keys in environment variables on the EC2 instance",
                "Use IAM roles attached to EC2 instances with appropriate S3 permissions",
                "Configure S3 bucket policies to allow access from EC2 instance public IPs",
                "Use AWS Systems Manager Parameter Store to store and retrieve credentials"
            ],
            correct: 1,
            explanation: {
                correct: "IAM roles for EC2 provide temporary, automatically rotated credentials without storing any secrets on the instance.",
                whyWrong: {
                    0: "Storing credentials on instances is a security risk and against best practices",
                    2: "IP-based access is not secure as IPs can change and doesn't provide identity-based access control",
                    3: "While Parameter Store is secure, IAM roles are the native, best-practice solution for EC2"
                },
                examStrategy: "IAM roles are always the answer for giving AWS services permissions to other AWS services. Never store credentials."
            }
        },
        {
            id: 'sec_005',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to implement a Web Application Firewall to protect their application from common web exploits and bots. The application runs on ALB with EC2 instances and experiences variable traffic patterns.",
            question: "Which AWS WAF implementation provides the BEST protection while maintaining cost efficiency?",
            options: [
                "AWS WAF with managed rule groups and rate-based rules on the ALB",
                "AWS Shield Advanced with DDoS response team support",
                "Amazon CloudFront with AWS WAF and geo-restriction policies",
                "AWS Network Firewall with custom Suricata rules"
            ],
            correct: 0,
            explanation: {
                correct: "AWS WAF on ALB with managed rules provides protection against OWASP Top 10 and bots, with pay-per-use pricing suitable for variable traffic.",
                whyWrong: {
                    1: "Shield Advanced is expensive ($3000/month) and focused on DDoS, not web application attacks",
                    2: "Adding CloudFront when not needed increases complexity and cost",
                    3: "Network Firewall is for network-level protection, not application-layer web exploits"
                },
                examStrategy: "AWS WAF protects against application layer (Layer 7) attacks. Shield protects against DDoS (Layer 3/4). Choose based on attack type."
            }
        },
        {
            id: 'sec_006',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company has a three-tier web application with public, private, and database subnets across multiple AZs. They need to allow developers to SSH into private EC2 instances for debugging without exposing them to the internet.",
            question: "What is the MOST secure solution for providing SSH access to private instances?",
            options: [
                "Deploy a bastion host in the public subnet with security group restrictions",
                "Use AWS Systems Manager Session Manager with VPC endpoints",
                "Configure AWS VPN Client with MFA for developer access",
                "Implement AWS Direct Connect with on-premises jump servers"
            ],
            correct: 1,
            explanation: {
                correct: "Session Manager provides secure shell access without SSH keys, bastion hosts, or open ports. VPC endpoints keep traffic private.",
                whyWrong: {
                    0: "Bastion hosts require maintenance, SSH key management, and expose port 22",
                    2: "VPN is more complex and still requires managing EC2 SSH access",
                    3: "Direct Connect is expensive and overly complex for developer access"
                },
                examStrategy: "Session Manager is the modern, serverless replacement for bastion hosts. No open ports, no SSH keys, full audit logging."
            }
        },
        {
            id: 'sec_007',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An e-commerce company needs to secure their API Gateway endpoints that serve mobile and web clients. They want to implement API throttling and require API key authentication.",
            question: "Which combination of API Gateway features provides the required security controls?",
            options: [
                "API Gateway usage plans with API keys and Lambda authorizers",
                "API Gateway resource policies with AWS WAF integration",
                "API Gateway with Cognito user pools and throttling settings",
                "API Gateway usage plans with API keys and throttling limits"
            ],
            correct: 3,
            explanation: {
                correct: "Usage plans provide API key management and throttling limits per API key, meeting both requirements directly.",
                whyWrong: {
                    0: "Lambda authorizers add unnecessary complexity when simple API key authentication is sufficient",
                    1: "Resource policies control access but don't provide API key management",
                    2: "Cognito is for user authentication, not API key-based authentication"
                },
                examStrategy: "API Gateway usage plans = API keys + throttling. Cognito = user authentication. Lambda authorizers = custom auth logic."
            }
        },
        {
            id: 'sec_008',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to ensure that all S3 buckets in their account block public access by default, even if developers accidentally misconfigure bucket policies.",
            question: "What is the MOST effective way to prevent public access to S3 buckets?",
            options: [
                "Enable S3 Block Public Access at the account level",
                "Use AWS Config rules to monitor bucket policies",
                "Implement Service Control Policies in AWS Organizations",
                "Configure S3 bucket policies with explicit deny statements"
            ],
            correct: 0,
            explanation: {
                correct: "S3 Block Public Access at the account level overrides any bucket policy or ACL that would make data public.",
                whyWrong: {
                    1: "Config monitors but doesn't prevent misconfigurations",
                    2: "SCPs are organization-level and require AWS Organizations setup",
                    3: "Bucket policies can be overridden by misconfiguration"
                },
                examStrategy: "S3 Block Public Access is the definitive control for preventing public access. Enable at account level for maximum protection."
            }
        },
        {
            id: 'sec_009',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to share sensitive documents stored in S3 with external partners for a limited time. The documents should only be accessible for 7 days.",
            question: "What is the MOST secure method to share these S3 objects with external partners?",
            options: [
                "Create IAM users for partners with temporary credentials",
                "Generate S3 presigned URLs with 7-day expiration",
                "Create a public S3 bucket with lifecycle policies",
                "Use AWS Transfer Family with SFTP and time-based access"
            ],
            correct: 1,
            explanation: {
                correct: "Presigned URLs provide temporary, secure access to specific S3 objects without requiring AWS credentials or permanent access changes.",
                whyWrong: {
                    0: "Creating IAM users for external partners is not recommended and harder to manage",
                    2: "Public buckets are insecure and lifecycle policies delete objects, not revoke access",
                    3: "Transfer Family is overly complex for simple temporary file sharing"
                },
                examStrategy: "Presigned URLs are the go-to solution for temporary, secure S3 object sharing with external parties."
            }
        },
        {
            id: 'sec_010',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A financial institution needs to implement network segmentation for their VPC hosting payment processing systems. They require inspection of all east-west traffic between subnets and north-south traffic to the internet.",
            question: "Which solution provides comprehensive traffic inspection and segmentation?",
            options: [
                "AWS Network Firewall with stateful rules and multiple route tables",
                "Multiple Security Groups with VPC Flow Logs and GuardDuty",
                "Transit Gateway with security VPC and third-party firewall appliances",
                "VPC Network ACLs with AWS WAF on ALB"
            ],
            correct: 0,
            explanation: {
                correct: "Network Firewall provides stateful inspection of all VPC traffic with centralized rule management for both east-west and north-south traffic.",
                whyWrong: {
                    1: "Security Groups don't inspect traffic content and can't enforce segmentation policies",
                    2: "Requires additional licensing and complex routing compared to native Network Firewall",
                    3: "NACLs are stateless and WAF only protects web traffic, not all network traffic"
                },
                examStrategy: "AWS Network Firewall is the native solution for VPC traffic inspection and segmentation. Use for compliance requirements."
            }
        },
        {
            id: 'sec_011',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to provide temporary database access to contractors working on a 3-month project. Contractors should only access specific databases during business hours.",
            question: "Which solution provides the MOST secure temporary access control?",
            options: [
                "IAM users with permission boundaries and time-based access policies",
                "IAM roles with external ID and AWS STS session policies",
                "Database users with password rotation via Secrets Manager",
                "Federated access using SAML 2.0 with session duration limits"
            ],
            correct: 3,
            explanation: {
                correct: "Federation with SAML provides temporary access without permanent credentials, with configurable session durations and easy revocation.",
                whyWrong: {
                    0: "IAM users create permanent credentials even with permission boundaries",
                    1: "External ID is for cross-account access, not time-based restrictions",
                    2: "Database users bypass IAM controls and are harder to audit"
                },
                examStrategy: "Federation for temporary external access. IAM roles for AWS-to-AWS access. Never create IAM users for temporary needs."
            }
        },
        {
            id: 'sec_012',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A government agency requires all API calls to be authenticated, encrypted, and logged with tamper-proof audit trails for 10 years. The logs must be searchable within minutes.",
            question: "Which architecture meets all security and compliance requirements?",
            options: [
                "API Gateway with IAM auth → CloudTrail → S3 with Object Lock → Athena",
                "ALB with Cognito → CloudWatch Logs → Elasticsearch → Glacier",
                "API Gateway with API keys → VPC Flow Logs → S3 → Redshift",
                "CloudFront with signed URLs → CloudTrail → DynamoDB → S3"
            ],
            correct: 0,
            explanation: {
                correct: "API Gateway with IAM provides strong authentication, CloudTrail offers tamper-proof logging, S3 Object Lock ensures immutability, and Athena enables quick searching.",
                whyWrong: {
                    1: "CloudWatch Logs can be modified and Elasticsearch is expensive for 10-year retention",
                    2: "API keys are not as secure as IAM, VPC Flow Logs don't capture API-level details",
                    3: "CloudFront logs don't provide API-level audit trails"
                },
                examStrategy: "CloudTrail + S3 Object Lock = tamper-proof audit logs. Athena for searching S3 data. This is the compliance gold standard."
            }
        },
        {
            id: 'sec_013',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A healthcare application needs to encrypt patient data in transit between microservices running in ECS tasks within the same VPC.",
            question: "What is the SIMPLEST way to encrypt inter-service communication?",
            options: [
                "AWS App Mesh with TLS encryption between services",
                "Application Load Balancer with SSL/TLS certificates",
                "VPN connections between ECS tasks",
                "AWS PrivateLink endpoints for each service"
            ],
            correct: 0,
            explanation: {
                correct: "App Mesh provides automatic mTLS encryption between services without application code changes.",
                whyWrong: {
                    1: "ALB handles external traffic, not direct service-to-service communication",
                    2: "VPN between tasks is overly complex and not practical",
                    3: "PrivateLink is for accessing AWS services, not inter-service communication"
                },
                examStrategy: "App Mesh for service mesh features including mTLS. ALB for external traffic. PrivateLink for AWS service access."
            }
        },
        {
            id: 'sec_014',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to detect and automatically remediate security groups that allow unrestricted SSH access (0.0.0.0/0 on port 22).",
            question: "Which service combination provides automated detection and remediation?",
            options: [
                "AWS Config rules with AWS Systems Manager automation",
                "Amazon GuardDuty with Lambda functions",
                "AWS Security Hub with CloudFormation",
                "Amazon Inspector with EC2 Run Command"
            ],
            correct: 0,
            explanation: {
                correct: "Config rules detect non-compliant security groups, and Systems Manager automation can automatically remediate them.",
                whyWrong: {
                    1: "GuardDuty detects threats, not configuration compliance",
                    2: "Security Hub aggregates findings but doesn't directly remediate",
                    3: "Inspector assesses instances, not security group configurations"
                },
                examStrategy: "Config = compliance checking. Systems Manager = automation/remediation. GuardDuty = threat detection."
            }
        },
        {
            id: 'sec_015',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A financial services firm needs to ensure their RDS databases are encrypted, backed up daily, and passwords are rotated every 30 days automatically.",
            question: "Which combination of services meets ALL these requirements?",
            options: [
                "RDS with KMS encryption, automated backups, and Secrets Manager rotation",
                "RDS with TDE, AWS Backup, and Lambda password rotation",
                "Aurora with default encryption, snapshots, and Parameter Store",
                "RDS with CloudHSM, Data Pipeline backups, and IAM authentication"
            ],
            correct: 0,
            explanation: {
                correct: "RDS supports KMS encryption natively, automated backups are built-in, and Secrets Manager handles automatic password rotation.",
                whyWrong: {
                    1: "Lambda password rotation requires custom code vs Secrets Manager's built-in feature",
                    2: "Parameter Store doesn't provide automatic rotation",
                    3: "Data Pipeline is unnecessary for RDS backups, CloudHSM is overkill"
                },
                examStrategy: "Secrets Manager for automatic credential rotation. RDS automated backups for simplicity. KMS for encryption."
            }
        },
        {
            id: 'sec_016',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A multinational corporation needs to implement data residency controls ensuring EU customer data never leaves EU regions, even for disaster recovery.",
            question: "Which architecture ensures data residency compliance while maintaining disaster recovery capabilities?",
            options: [
                "S3 buckets in EU regions with Same-Region Replication and bucket policies restricting cross-region access",
                "S3 with Cross-Region Replication to another EU region and SCPs blocking non-EU access",
                "S3 in single EU region with versioning and MFA delete",
                "S3 with global bucket acceleration and geo-restriction"
            ],
            correct: 1,
            explanation: {
                correct: "CRR between EU regions provides DR while SCPs at the organization level enforce data residency by preventing any non-EU region access.",
                whyWrong: {
                    0: "Same-Region Replication doesn't provide regional DR capabilities",
                    2: "Single region doesn't provide regional disaster recovery",
                    3: "Global acceleration could route data through non-EU regions"
                },
                examStrategy: "SCPs provide organization-wide preventive controls. Use for compliance requirements that must never be violated."
            }
        },
        {
            id: 'sec_017',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to secure their container images in ECR and ensure only vulnerability-free images are deployed to production ECS clusters.",
            question: "Which solution prevents vulnerable container images from being deployed?",
            options: [
                "ECR image scanning with Lambda function to check results before ECS deployment",
                "ECR with image immutability and AWS Inspector continuous scanning",
                "GuardDuty container threat detection with automatic remediation",
                "Security Hub with container insights and CloudWatch alarms"
            ],
            correct: 0,
            explanation: {
                correct: "ECR image scanning identifies vulnerabilities, and Lambda can verify scan results as part of the deployment pipeline, blocking vulnerable images.",
                whyWrong: {
                    1: "Image immutability prevents overwrites but doesn't check vulnerabilities",
                    2: "GuardDuty detects runtime threats, not image vulnerabilities",
                    3: "Security Hub aggregates findings but doesn't block deployments"
                },
                examStrategy: "ECR scanning for container vulnerabilities. Lambda for custom deployment controls. Inspector for running instances."
            }
        },
        {
            id: 'sec_018',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "Developers need to access production CloudWatch logs for debugging but should not be able to modify or delete them.",
            question: "Which IAM policy action should be allowed for read-only CloudWatch Logs access?",
            options: [
                "logs:Describe*, logs:Get*, logs:List*, logs:Filter*",
                "logs:*",
                "cloudwatch:GetMetricData, cloudwatch:ListMetrics",
                "logs:CreateLogGroup, logs:CreateLogStream"
            ],
            correct: 0,
            explanation: {
                correct: "These actions provide read-only access to logs without any modification capabilities.",
                whyWrong: {
                    1: "logs:* includes dangerous actions like DeleteLogGroup",
                    2: "These are CloudWatch metrics actions, not logs",
                    3: "Create actions allow modification, not read-only"
                },
                examStrategy: "Describe/Get/List = read operations. Create/Put/Delete/Update = write operations. Filter is read-only for logs."
            }
        },
        {
            id: 'sec_019',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company requires all EC2 instances to be launched with specific security configurations including IMDSv2, monitoring enabled, and encrypted volumes.",
            question: "How can these requirements be enforced across all EC2 launches?",
            options: [
                "Service Control Policies with EC2 launch conditions",
                "AWS Config rules with auto-remediation",
                "EC2 launch templates with IAM restrictions",
                "CloudFormation with stack policies"
            ],
            correct: 0,
            explanation: {
                correct: "SCPs can enforce conditions on EC2 launches, preventing any instance from starting without required configurations.",
                whyWrong: {
                    1: "Config rules detect after launch, not prevent",
                    2: "Launch templates provide defaults but don't enforce",
                    3: "Stack policies only apply to CloudFormation stacks"
                },
                examStrategy: "SCPs for preventive organizational controls. Config for detective controls. Launch templates for standardization."
            }
        },
        {
            id: 'sec_020',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A bank needs to implement a payment processing system where encryption keys are split between two parties and both must participate to decrypt sensitive data.",
            question: "Which solution provides cryptographic key splitting with dual control?",
            options: [
                "AWS CloudHSM with M of N access control for key operations",
                "KMS multi-region keys with cross-region replication",
                "Secrets Manager with resource-based policies",
                "KMS envelope encryption with separate data keys"
            ],
            correct: 0,
            explanation: {
                correct: "CloudHSM supports M of N access control where multiple parties must authenticate for cryptographic operations, implementing true dual control.",
                whyWrong: {
                    1: "Multi-region keys replicate keys, don't split control",
                    2: "Secrets Manager doesn't provide cryptographic dual control",
                    3: "Envelope encryption doesn't split key control between parties"
                },
                examStrategy: "CloudHSM for hardware-based security and advanced cryptographic controls. KMS for standard encryption needs."
            }
        },
        {
            id: 'sec_021',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An application stores credit card data temporarily in memory for processing. The company wants to ensure this data is never written to disk or swap space.",
            question: "Which EC2 configuration ensures sensitive data in memory is never persisted to disk?",
            options: [
                "Nitro instances with encrypted memory and disabled hibernation",
                "Instances with encrypted EBS volumes and disabled swap",
                "Dedicated hosts with host-level encryption",
                "Spot instances with ephemeral storage only"
            ],
            correct: 1,
            explanation: {
                correct: "Disabling swap prevents memory from being written to disk, and encrypted EBS provides defense in depth if data accidentally persists.",
                whyWrong: {
                    0: "Nitro doesn't provide encrypted memory by default",
                    2: "Dedicated hosts don't prevent swap to disk",
                    3: "Spot instances can still use swap space"
                },
                examStrategy: "Disable swap for sensitive in-memory data. Encrypted EBS for data at rest. Nitro for enhanced security features."
            }
        },
        {
            id: 'sec_022',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A startup wants to ensure their AWS account follows security best practices from day one.",
            question: "Which AWS service provides automated security best practice checks?",
            options: [
                "AWS Security Hub with AWS Foundational Security Best Practices",
                "AWS Shield Standard",
                "Amazon Macie",
                "AWS WAF with managed rules"
            ],
            correct: 0,
            explanation: {
                correct: "Security Hub with Foundational Security Best Practices automatically checks against AWS security recommendations.",
                whyWrong: {
                    1: "Shield protects against DDoS, not general security practices",
                    2: "Macie focuses on data security in S3",
                    3: "WAF protects web applications, not account-wide security"
                },
                examStrategy: "Security Hub = central security dashboard. Trusted Advisor = general best practices. Well-Architected Tool = architecture review."
            }
        },
        {
            id: 'sec_023',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to share AMIs with specific AWS accounts while ensuring the AMIs cannot be made public or shared with unauthorized accounts.",
            question: "How should AMI sharing be configured with these restrictions?",
            options: [
                "Share AMIs with specific account IDs and enable AMI block public access",
                "Use AWS Resource Access Manager with strict sharing policies",
                "Copy AMIs to shared S3 buckets with bucket policies",
                "Use Service Catalog to control AMI distribution"
            ],
            correct: 0,
            explanation: {
                correct: "Direct AMI sharing with specific accounts combined with block public access ensures controlled distribution.",
                whyWrong: {
                    1: "RAM doesn't support AMI sharing",
                    2: "S3 bucket sharing is complex and loses AMI functionality",
                    3: "Service Catalog is for product distribution, not AMI sharing control"
                },
                examStrategy: "AMIs can be shared directly with account IDs. Block public access prevents accidental exposure. RAM for other resource types."
            }
        },
        {
            id: 'sec_024',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A defense contractor must implement a system where data is encrypted with keys that are destroyed after processing, ensuring perfect forward secrecy.",
            question: "Which architecture provides perfect forward secrecy with automatic key destruction?",
            options: [
                "Lambda with KMS data keys generated per invocation and automatic cleanup",
                "ECS with CloudHSM session keys and container termination",
                "EC2 with AWS Nitro Enclaves and ephemeral key generation",
                "Fargate with Secrets Manager and automatic rotation"
            ],
            correct: 2,
            explanation: {
                correct: "Nitro Enclaves provide isolated compute with ephemeral keys that are automatically destroyed when the enclave terminates, ensuring perfect forward secrecy.",
                whyWrong: {
                    0: "Lambda KMS keys can be logged in CloudTrail",
                    1: "CloudHSM session keys require manual management",
                    3: "Secrets Manager rotation doesn't destroy old keys immediately"
                },
                examStrategy: "Nitro Enclaves for highest security isolation and ephemeral processing. CloudHSM for key management. KMS for general encryption."
            }
        },
        {
            id: 'sec_025',
            domain: "Domain 1: Design Secure Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to ensure that deleted S3 objects can be recovered for 30 days but are permanently removed after that period to comply with data retention policies.",
            question: "Which S3 configuration meets these requirements?",
            options: [
                "Enable versioning with lifecycle rules to delete versions after 30 days",
                "Enable MFA Delete with 30-day recovery window",
                "Configure S3 Object Lock with 30-day retention",
                "Use S3 Intelligent-Tiering with archive settings"
            ],
            correct: 0,
            explanation: {
                correct: "Versioning preserves deleted objects as previous versions, and lifecycle rules automatically remove them after 30 days.",
                whyWrong: {
                    1: "MFA Delete prevents deletion, doesn't provide automatic removal",
                    2: "Object Lock prevents deletion during retention period",
                    3: "Intelligent-Tiering is for storage optimization, not deletion recovery"
                },
                examStrategy: "Versioning for soft delete/recovery. Object Lock for compliance/legal hold. Lifecycle for automatic transitions/deletions."
            }
        },
        // Continue with more security questions...
        {
        id: 'sec_026',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to securely store and manage database connection strings, API keys, and other secrets for their applications running on EC2 and Lambda.",
        question: "Which solution provides the MOST secure and scalable secrets management?",
        options: [
            "AWS Secrets Manager with automatic rotation and IAM integration",
            "AWS Systems Manager Parameter Store with SecureString parameters",
            "Encrypted environment variables in Lambda and EC2 user data",
            "HashiCorp Vault running on EC2 instances"
        ],
        correct: 0,
        explanation: {
            correct: "Secrets Manager provides native automatic rotation, versioning, and fine-grained IAM access control with audit logging.",
            whyWrong: {
                1: "Parameter Store lacks automatic rotation capabilities for database credentials",
                2: "Environment variables and user data are not centrally managed and harder to rotate",
                3: "Self-managed Vault requires additional infrastructure and maintenance"
            },
            examStrategy: "Secrets Manager for automatic rotation needs. Parameter Store for simple configs. Never hardcode secrets."
        }
    },
    {
        id: 'sec_027',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial institution requires all data to be encrypted with customer-controlled keys, including EBS volumes, S3 objects, and RDS databases. They need centralized key management with detailed audit trails.",
        question: "Which encryption strategy provides comprehensive control and auditability?",
        options: [
            "AWS KMS with customer-managed CMKs, CloudTrail logging, and key policies",
            "AWS CloudHSM with custom key management application",
            "Client-side encryption with keys stored in Parameter Store",
            "AWS Certificate Manager with private certificate authority"
        ],
        correct: 0,
        explanation: {
            correct: "KMS with CMKs provides centralized management across all services with CloudTrail integration for complete audit trails.",
            whyWrong: {
                1: "CloudHSM requires more complex integration with various services",
                2: "Client-side encryption doesn't work natively with RDS",
                3: "ACM is for SSL/TLS certificates, not data encryption"
            },
            examStrategy: "KMS for centralized key management across AWS services. CloudHSM for regulatory requirements needing FIPS 140-2 Level 3."
        }
    },
    {
        id: 'sec_028',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company wants to restrict S3 bucket access to only their corporate network and specific VPC endpoints, blocking all internet access.",
        question: "Which combination of controls provides the STRONGEST access restrictions?",
        options: [
            "S3 bucket policy with aws:SourceIp and aws:SourceVpce conditions",
            "S3 Block Public Access and VPC endpoint policies",
            "AWS WAF with IP restrictions on S3 bucket URLs",
            "Security groups on S3 VPC endpoints"
        ],
        correct: 0,
        explanation: {
            correct: "Bucket policies with IP and VPC endpoint conditions provide explicit allow lists for authorized access sources.",
            whyWrong: {
                1: "Block Public Access alone doesn't restrict to specific IPs or VPCs",
                2: "WAF doesn't work with S3 directly",
                3: "Security groups can't be applied to S3 service endpoints"
            },
            examStrategy: "Use bucket policies for S3 access control. Combine multiple conditions for defense in depth. VPC endpoints for private connectivity."
        }
    },
    {
        id: 'sec_029',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A developer accidentally committed AWS access keys to a public GitHub repository. The keys have full administrative access.",
        question: "What should be done IMMEDIATELY to secure the account?",
        options: [
            "Delete the GitHub repository",
            "Rotate the compromised access keys in IAM",
            "Enable MFA on the root account",
            "Change the account password"
        ],
        correct: 1,
        explanation: {
            correct: "Immediately rotating (deactivating and deleting) the compromised keys prevents their use, even if already downloaded by attackers.",
            whyWrong: {
                0: "Deleting the repo doesn't invalidate already-exposed keys",
                2: "MFA is important but doesn't stop use of exposed access keys",
                3: "Password change doesn't affect programmatic access keys"
            },
            examStrategy: "Compromised credentials = immediate rotation. Assume keys are compromised once exposed publicly. Enable CloudTrail to audit usage."
        }
    },
    {
        id: 'sec_030',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A healthcare application needs to log all API calls for HIPAA compliance while ensuring logs cannot be tampered with or deleted for 7 years.",
        question: "Which solution provides immutable audit logging?",
        options: [
            "CloudTrail with S3 Object Lock in compliance mode and MFA Delete",
            "CloudWatch Logs with retention policies and encryption",
            "AWS Config with conformance packs and remediation",
            "VPC Flow Logs with S3 lifecycle policies"
        ],
        correct: 0,
        explanation: {
            correct: "CloudTrail captures all API calls, S3 Object Lock in compliance mode prevents deletion, and MFA Delete adds additional protection.",
            whyWrong: {
                1: "CloudWatch Logs can be modified and don't capture all API calls",
                2: "Config tracks resource changes, not all API calls",
                3: "VPC Flow Logs only capture network traffic, not API calls"
            },
            examStrategy: "CloudTrail + S3 Object Lock = immutable audit trail. Compliance mode prevents deletion even by root user."
        }
    },
    {
        id: 'sec_031',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A multi-tenant SaaS platform needs to ensure complete isolation between customer data while allowing customers to bring their own encryption keys.",
        question: "Which architecture provides the STRONGEST tenant isolation with customer-managed encryption?",
        options: [
            "Separate AWS accounts per tenant with AWS KMS cross-account key sharing",
            "Single account with IAM policies and customer KMS keys",
            "AWS Organizations with SCPs and consolidated key management",
            "Resource tagging with ABAC and envelope encryption"
        ],
        correct: 0,
        explanation: {
            correct: "Separate accounts provide the strongest isolation boundary, and KMS supports cross-account key sharing for customer-managed keys.",
            whyWrong: {
                1: "Single account risks cross-tenant access through misconfigurations",
                2: "Organizations provide management but not isolation",
                3: "Tagging and ABAC are less secure than account boundaries"
            },
            examStrategy: "Account separation for strong multi-tenant isolation. KMS supports cross-account key grants. Account = strongest AWS boundary."
        }
    },
    {
        id: 'sec_032',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An application needs to validate that uploaded files are free from malware before processing them. Files range from 1MB to 500MB.",
        question: "Which solution provides scalable malware scanning for uploaded files?",
        options: [
            "S3 event triggers Lambda which calls third-party antivirus API",
            "EC2 instances with antivirus software polling S3",
            "AWS GuardDuty with S3 protection enabled",
            "Amazon Macie with custom data identifiers"
        ],
        correct: 0,
        explanation: {
            correct: "Lambda with third-party AV APIs provides serverless, scalable scanning triggered automatically on upload.",
            whyWrong: {
                1: "EC2 polling is less efficient and requires infrastructure management",
                2: "GuardDuty detects threats but doesn't scan file contents for malware",
                3: "Macie identifies sensitive data, not malware"
            },
            examStrategy: "Lambda for event-driven processing. GuardDuty for threat detection. Macie for data classification. Know service capabilities."
        }
    },
    {
        id: 'sec_033',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to ensure that all EBS volumes are encrypted by default across their AWS account.",
        question: "How can default EBS encryption be enforced?",
        options: [
            "Enable EBS encryption by default in EC2 settings for the region",
            "Create IAM policies requiring encryption",
            "Use AWS Config rules to check encryption",
            "Modify each volume after creation"
        ],
        correct: 0,
        explanation: {
            correct: "EBS encryption by default is a region-level setting that automatically encrypts all new EBS volumes.",
            whyWrong: {
                1: "IAM policies can't enforce encryption at volume creation",
                2: "Config rules detect but don't prevent unencrypted volumes",
                3: "Post-creation modification is reactive, not preventive"
            },
            examStrategy: "Enable EBS encryption by default for automatic encryption. It's a per-region setting. Uses AWS managed keys unless specified."
        }
    },
    {
        id: 'sec_034',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement private connectivity between their on-premises data center and multiple VPCs across different AWS regions.",
        question: "Which solution provides secure, private connectivity with the LEAST complexity?",
        options: [
            "AWS Transit Gateway with Direct Connect and Transit VIFs",
            "Individual VPN connections to each VPC",
            "VPC peering with Site-to-Site VPN",
            "AWS PrivateLink endpoints in each VPC"
        ],
        correct: 0,
        explanation: {
            correct: "Transit Gateway acts as a cloud router, simplifying multi-VPC connectivity, while Direct Connect provides dedicated private connectivity.",
            whyWrong: {
                1: "Individual VPNs create management complexity and don't scale well",
                2: "VPC peering doesn't support on-premises connectivity",
                3: "PrivateLink is for service endpoints, not site-to-site connectivity"
            },
            examStrategy: "Transit Gateway for hub-and-spoke networking. Direct Connect for dedicated bandwidth. Simplify multi-VPC architectures."
        }
    },
    {
        id: 'sec_035',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company processing credit card payments needs to minimize PCI DSS scope while maintaining high availability for their payment processing system.",
        question: "Which architecture BEST reduces PCI compliance scope?",
        options: [
            "Separate VPC for payment processing with tokenization and API Gateway",
            "Single VPC with security groups isolating payment systems",
            "Lambda functions processing payments with VPC endpoints",
            "Containers on Fargate with service mesh encryption"
        ],
        correct: 0,
        explanation: {
            correct: "Isolated VPC with tokenization replaces card data with tokens, dramatically reducing systems that handle actual card data.",
            whyWrong: {
                1: "Single VPC increases scope to entire VPC",
                2: "Lambda still processes card data, maintaining scope",
                3: "Containers don't inherently reduce PCI scope"
            },
            examStrategy: "Network isolation and tokenization reduce PCI scope. Separate VPCs for compliance boundaries. Minimize systems touching card data."
        }
    },
    {
        id: 'sec_036',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to detect and automatically block IP addresses that are making suspicious requests to their web application.",
        question: "Which solution provides automated threat response?",
        options: [
            "AWS WAF with rate-based rules and Lambda for IP set updates",
            "GuardDuty with manual Security Group updates",
            "CloudWatch Logs with metric filters and alarms",
            "AWS Shield Advanced with DDoS Response Team"
        ],
        correct: 0,
        explanation: {
            correct: "WAF rate-based rules automatically detect anomalies, Lambda can update IP sets to block malicious IPs dynamically.",
            whyWrong: {
                1: "Manual updates are slow and don't scale",
                2: "CloudWatch alarms notify but don't block",
                3: "Shield Advanced is expensive and focused on DDoS, not application attacks"
            },
            examStrategy: "WAF for application-layer protection. Automate response with Lambda. Rate-based rules for dynamic threats."
        }
    },
    {
        id: 'sec_037',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to ensure that their RDS database backups are encrypted.",
        question: "How are encrypted RDS backup snapshots created?",
        options: [
            "Snapshots are automatically encrypted if the source database is encrypted",
            "Enable encryption when creating each snapshot",
            "Use AWS Backup with encryption settings",
            "Export snapshots to S3 with encryption"
        ],
        correct: 0,
        explanation: {
            correct: "RDS automatically encrypts snapshots using the same key as the source database when the database is encrypted.",
            whyWrong: {
                1: "You can't encrypt snapshots from unencrypted databases directly",
                2: "AWS Backup uses source database encryption settings",
                3: "Exporting adds complexity and doesn't change source encryption"
            },
            examStrategy: "Encrypted database = encrypted snapshots automatically. Can't directly encrypt snapshots from unencrypted databases."
        }
    },
    {
        id: 'sec_038',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement least privilege access for developers who need to debug production issues without accessing sensitive data.",
        question: "Which solution provides debugging access while protecting sensitive data?",
        options: [
            "Session Manager with session logging and restricted IAM policies",
            "Bastion hosts with full SSH access",
            "Read-only IAM roles with CloudWatch Logs access",
            "VPN with Active Directory integration"
        ],
        correct: 0,
        explanation: {
            correct: "Session Manager provides controlled access without SSH keys, with full audit logging and IAM-based restrictions.",
            whyWrong: {
                1: "Bastion hosts with full SSH provide too much access",
                2: "Read-only roles might not allow necessary debugging actions",
                3: "VPN provides network access but not application-level controls"
            },
            examStrategy: "Session Manager for secure access without SSH. IAM for fine-grained permissions. Always audit privileged access."
        }
    },
    {
        id: 'sec_039',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A global company needs to comply with data residency laws ensuring EU data never leaves the EU region, even for backup or disaster recovery.",
        question: "Which backup strategy ensures compliance with data residency requirements?",
        options: [
            "AWS Backup with vault lock and backup policies restricted to EU regions",
            "Cross-Region replication to another EU region with SCPs blocking non-EU access",
            "S3 lifecycle policies with Glacier storage in EU",
            "EBS snapshots with customer-managed KMS keys"
        ],
        correct: 1,
        explanation: {
            correct: "CRR within EU regions maintains data residency while SCPs prevent any access from non-EU regions organizationally.",
            whyWrong: {
                0: "Backup vaults can be accessed globally without additional controls",
                2: "Lifecycle policies don't prevent cross-region access",
                3: "KMS keys don't enforce regional restrictions"
            },
            examStrategy: "SCPs for organizational compliance boundaries. Keep data and backups within required regions. Preventive controls over detective."
        }
    },
    {
        id: 'sec_040',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to securely share large datasets with external research partners on a regular basis. Partners should only access specific datasets.",
        question: "What is the MOST secure method for sharing data with external partners?",
        options: [
            "S3 Access Points with cross-account access policies",
            "IAM roles with external ID for partner accounts",
            "Pre-signed URLs generated for each dataset",
            "AWS Transfer Family with SFTP and user isolation"
        ],
        correct: 0,
        explanation: {
            correct: "S3 Access Points provide dedicated endpoints with specific policies for each partner, enabling fine-grained access control.",
            whyWrong: {
                1: "IAM roles with external ID are better for service access, not data sharing",
                2: "Pre-signed URLs don't scale well for regular, ongoing access",
                3: "Transfer Family adds complexity for S3-based sharing"
            },
            examStrategy: "S3 Access Points for complex sharing scenarios. Pre-signed URLs for temporary access. IAM roles for cross-account service access."
        }
    },
    {
        id: 'sec_041',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to prevent root user access to their production AWS accounts.",
        question: "What is the AWS best practice for root user access management?",
        options: [
            "Enable MFA, create IAM users for daily tasks, and secure root credentials",
            "Delete root user access keys and disable the account",
            "Use AWS SSO exclusively and block root login",
            "Rotate root password daily using Lambda"
        ],
        correct: 0,
        explanation: {
            correct: "Best practice is to secure root with MFA, remove access keys, and use IAM users/roles for all regular activities.",
            whyWrong: {
                1: "You cannot disable root account entirely",
                2: "SSO cannot replace root user for certain account operations",
                3: "Automated root password rotation is not recommended"
            },
            examStrategy: "Root user = break glass emergency access only. Always use MFA. Never create root access keys. Use IAM for daily operations."
        }
    },
    {
        id: 'sec_042',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their Lambda functions can only be invoked by specific API Gateway endpoints and not directly.",
        question: "How should Lambda function invocation be restricted?",
        options: [
            "Lambda resource-based policy with sourceArn condition",
            "VPC endpoints for Lambda service",
            "IAM roles with trust relationships",
            "Lambda layers with authentication logic"
        ],
        correct: 0,
        explanation: {
            correct: "Resource-based policies with sourceArn condition ensure Lambda can only be invoked by specific API Gateway ARNs.",
            whyWrong: {
                1: "VPC endpoints don't control what can invoke Lambda",
                2: "IAM roles control what Lambda can access, not what can invoke it",
                3: "Layers provide shared code, not invocation control"
            },
            examStrategy: "Resource-based policies for Lambda invocation control. SourceArn for specific resource restrictions. Different from execution role."
        }
    },
    {
        id: 'sec_043',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial services company needs to implement a complete audit trail of all database queries, including SELECT statements, with real-time alerting for suspicious patterns.",
        question: "Which solution provides comprehensive database auditing with real-time analysis?",
        options: [
            "Aurora with Database Activity Streams sent to Kinesis for analysis",
            "RDS with CloudTrail logging and CloudWatch alarms",
            "DynamoDB Streams with Lambda processing",
            "RDS Performance Insights with enhanced monitoring"
        ],
        correct: 0,
        explanation: {
            correct: "Database Activity Streams captures all database activity including SELECTs in near real-time, Kinesis enables real-time analysis.",
            whyWrong: {
                1: "CloudTrail doesn't capture SELECT statements, only API calls",
                2: "DynamoDB Streams only captures data changes, not reads",
                3: "Performance Insights is for performance metrics, not security auditing"
            },
            examStrategy: "Database Activity Streams for complete database auditing. CloudTrail for API calls only. Know what each service audits."
        }
    },
    {
        id: 'sec_044',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure that EC2 instances can only be launched from approved AMIs that have passed security scanning.",
        question: "How can AMI usage be restricted to approved images only?",
        options: [
            "Service Control Policy with ec2:ImageId condition",
            "AWS Config rule checking AMI IDs",
            "IAM policy with AMI restrictions",
            "Systems Manager Parameter Store with approved AMI list"
        ],
        correct: 0,
        explanation: {
            correct: "SCPs with ImageId condition can prevent launching EC2 instances from non-approved AMIs across the organization.",
            whyWrong: {
                1: "Config rules detect but don't prevent non-compliant launches",
                2: "IAM policies can be overridden by users with administrative access",
                3: "Parameter Store stores data but doesn't enforce restrictions"
            },
            examStrategy: "SCPs for preventive controls across organizations. Config for detective controls. IAM for user-level permissions."
        }
    },
    {
        id: 'sec_045',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to enable MFA for all IAM users accessing the AWS Console.",
        question: "How can MFA be enforced for console access?",
        options: [
            "IAM policy denying actions without MFA condition",
            "Enable MFA in account settings",
            "Use AWS SSO with MFA requirement",
            "CloudTrail monitoring for non-MFA access"
        ],
        correct: 0,
        explanation: {
            correct: "IAM policies with 'aws:MultiFactorAuthPresent' condition can deny actions for users without MFA.",
            whyWrong: {
                1: "There's no account-wide MFA setting for IAM users",
                2: "SSO is separate from IAM user MFA",
                3: "CloudTrail monitors but doesn't enforce"
            },
            examStrategy: "Use IAM policy conditions to enforce MFA. 'aws:MultiFactorAuthPresent' for MFA enforcement. Consider SSO for centralized auth."
        }
    },
    {
        id: 'sec_046',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to automatically rotate passwords for their RDS MySQL databases every 30 days without application downtime.",
        question: "Which solution provides zero-downtime password rotation?",
        options: [
            "Secrets Manager with Lambda rotation function and multi-user rotation strategy",
            "Systems Manager automation with maintenance windows",
            "RDS proxy with IAM authentication",
            "Parameter Store with CloudWatch Events triggers"
        ],
        correct: 0,
        explanation: {
            correct: "Secrets Manager with multi-user rotation creates a new user, updates the secret, then removes the old user, ensuring no downtime.",
            whyWrong: {
                1: "Systems Manager automation might cause brief connection interruptions",
                2: "RDS Proxy with IAM doesn't rotate database passwords",
                3: "Parameter Store doesn't have built-in rotation functionality"
            },
            examStrategy: "Secrets Manager for automated rotation. Multi-user strategy for zero downtime. Single-user strategy has brief unavailability."
        }
    },
    {
        id: 'sec_047',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A healthcare company needs to implement end-to-end encryption for patient data flowing through their microservices architecture, including service-to-service communication.",
        question: "Which solution provides comprehensive encryption for microservices communication?",
        options: [
            "AWS App Mesh with mTLS enabled between all services",
            "API Gateway with SSL termination at each service",
            "Network Load Balancer with TLS passthrough",
            "VPN connections between service subnets"
        ],
        correct: 0,
        explanation: {
            correct: "App Mesh provides automatic mTLS encryption between all microservices without application code changes.",
            whyWrong: {
                1: "API Gateway doesn't handle east-west traffic between services",
                2: "NLB with passthrough requires application-level TLS implementation",
                3: "VPN between subnets is overly complex and doesn't provide application-level encryption"
            },
            examStrategy: "App Mesh for service mesh capabilities including mTLS. API Gateway for north-south traffic. Know the difference."
        }
    },
    {
        id: 'sec_048',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to detect when S3 objects containing PII are made public accidentally.",
        question: "Which combination of services provides detection and alerting for public PII exposure?",
        options: [
            "Macie for PII detection with EventBridge for public access alerts",
            "GuardDuty with S3 protection and CloudWatch alarms",
            "Config rules with Lambda remediation",
            "Access Analyzer with SNS notifications"
        ],
        correct: 0,
        explanation: {
            correct: "Macie identifies PII in S3 objects and EventBridge can trigger alerts when Macie detects publicly accessible sensitive data.",
            whyWrong: {
                1: "GuardDuty doesn't scan for PII content",
                2: "Config checks configurations, not data content",
                3: "Access Analyzer identifies public access but not PII"
            },
            examStrategy: "Macie for data classification. Access Analyzer for resource exposure. Combine services for comprehensive detection."
        }
    },
    {
        id: 'sec_049',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A startup wants to implement security best practices with minimal configuration effort.",
        question: "Which service provides automated security recommendations out-of-the-box?",
        options: [
            "AWS Security Hub with AWS Foundational Security Best Practices",
            "Amazon Inspector with network assessments",
            "AWS WAF with managed rule groups",
            "Amazon Detective with finding groups"
        ],
        correct: 0,
        explanation: {
            correct: "Security Hub automatically runs foundational security checks and provides prioritized recommendations without configuration.",
            whyWrong: {
                1: "Inspector requires agent installation and assessment configuration",
                2: "WAF requires manual rule configuration",
                3: "Detective is for investigation after incidents, not proactive recommendations"
            },
            examStrategy: "Security Hub for centralized security posture. Foundational Security Best Practices for automatic checks. Low effort security."
        }
    },
    {
        id: 'sec_050',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure that only specific AWS services can assume their IAM roles, preventing confused deputy attacks.",
        question: "Which IAM trust policy element prevents confused deputy attacks?",
        options: [
            "ExternalId with a unique, hard-to-guess value",
            "Principal with specific service names",
            "MFA condition in the trust policy",
            "IP address restrictions in conditions"
        ],
        correct: 0,
        explanation: {
            correct: "ExternalId with a unique value ensures that only the intended third party can assume the role, preventing confused deputy attacks.",
            whyWrong: {
                1: "Service principals alone don't prevent confused deputy scenarios",
                2: "MFA doesn't apply to service-to-service role assumption",
                3: "IP restrictions don't prevent service-based attacks"
            },
            examStrategy: "ExternalId for third-party role assumption. Confused deputy = service tricked into misusing permissions. Always use with cross-account roles."
        }
    },

 {
        id: 'sec_051',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement certificate management for their fleet of 100,000 IoT devices. Each device requires unique certificates with automatic rotation.",
        question: "Which solution provides the MOST scalable certificate management for IoT devices?",
        options: [
            "AWS IoT Core with X.509 certificates and Just-In-Time provisioning",
            "AWS Certificate Manager with exported certificates to S3",
            "AWS Systems Manager with custom certificate rotation",
            "Third-party PKI solution on EC2"
        ],
        correct: 0,
        explanation: {
            correct: "IoT Core with JIT provisioning scales to millions of devices with automatic certificate management and rotation.",
            whyWrong: {
                1: "ACM doesn't support IoT device certificates directly",
                2: "Systems Manager not designed for IoT certificate management at scale",
                3: "Third-party PKI requires significant management overhead"
            },
            examStrategy: "IoT Core for IoT security at scale. JIT provisioning for automatic device onboarding. Built-in certificate lifecycle management."
        }
    },
    {
        id: 'sec_052',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A healthcare organization must implement end-to-end encryption for patient data flowing through multiple AWS services while maintaining the ability to search encrypted data.",
        question: "Which architecture enables searchable encryption while maintaining HIPAA compliance?",
        options: [
            "Client-side encryption with AWS KMS and encrypted search indexes in ElasticSearch",
            "S3 server-side encryption with CloudSearch for indexing",
            "RDS with Transparent Data Encryption and full-text search",
            "DynamoDB encryption with plaintext global secondary indexes"
        ],
        correct: 0,
        explanation: {
            correct: "Client-side encryption ensures data is encrypted before reaching AWS, with encrypted indexes maintaining searchability without exposing plaintext.",
            whyWrong: {
                1: "CloudSearch would require decrypted data for indexing",
                2: "TDE doesn't provide end-to-end encryption",
                3: "Plaintext indexes violate end-to-end encryption requirements"
            },
            examStrategy: "Client-side encryption for end-to-end security. Encrypted search indexes for compliance. Healthcare = highest security standards."
        }
    },
    {
        id: 'sec_053',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A fintech startup needs to implement PCI DSS compliant network segmentation with inspection of all payment card data flows.",
        question: "Which network architecture provides PCI DSS compliant segmentation and monitoring?",
        options: [
            "Separate VPCs for CDE and non-CDE with AWS Network Firewall between them",
            "Single VPC with Security Groups isolating payment systems",
            "Transit Gateway with route tables for segmentation",
            "VPC peering with Network ACLs for isolation"
        ],
        correct: 0,
        explanation: {
            correct: "Separate VPCs provide true network isolation for Cardholder Data Environment (CDE), with Network Firewall enabling required traffic inspection.",
            whyWrong: {
                1: "Security Groups alone don't provide sufficient segmentation for PCI DSS",
                2: "Transit Gateway doesn't provide traffic inspection capabilities",
                3: "VPC peering doesn't allow inline traffic inspection"
            },
            examStrategy: "PCI DSS requires network segmentation and traffic inspection. Network Firewall for compliance-grade inspection."
        }
    },
    {
        id: 'sec_054',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to ensure that all new S3 buckets are encrypted by default across their organization.",
        question: "What is the MOST effective way to enforce default encryption for all new S3 buckets?",
        options: [
            "Service Control Policy requiring s3:x-amz-server-side-encryption",
            "AWS Config rule with auto-remediation",
            "CloudFormation templates with encryption configured",
            "S3 bucket policies on each bucket"
        ],
        correct: 0,
        explanation: {
            correct: "SCPs prevent bucket creation without encryption, enforcing the requirement at the organization level.",
            whyWrong: {
                1: "Config rules detect after creation, not preventive",
                2: "CloudFormation only works for resources created via templates",
                3: "Bucket policies require individual configuration per bucket"
            },
            examStrategy: "SCPs for preventive organization-wide controls. Enforce security requirements at creation time, not after."
        }
    },
    {
        id: 'sec_055',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to provide third-party auditors with read-only access to CloudTrail logs without giving them AWS account access.",
        question: "Which solution provides secure, auditor-accessible CloudTrail logs?",
        options: [
            "S3 presigned URLs with time-limited access to specific log files",
            "Cross-account role with read-only permissions",
            "CloudTrail Lake with external query access",
            "AWS SSO with temporary auditor accounts"
        ],
        correct: 0,
        explanation: {
            correct: "Presigned URLs provide time-limited access to specific logs without requiring AWS credentials or account access.",
            whyWrong: {
                1: "Cross-account roles still require AWS account access",
                2: "CloudTrail Lake doesn't support external non-AWS access",
                3: "AWS SSO creates actual AWS access, not desired for external auditors"
            },
            examStrategy: "Presigned URLs for temporary external access. No AWS credentials needed. Time-bound and file-specific access control."
        }
    },
    {
        id: 'sec_056',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A government contractor must implement a zero-trust architecture where no service trusts any other service by default, even within the same VPC.",
        question: "Which combination implements zero-trust networking in AWS?",
        options: [
            "AWS PrivateLink for all service communication with IAM authentication and VPC endpoint policies",
            "Transit Gateway with centralized inspection VPC",
            "Service mesh with mTLS between all services",
            "Network Firewall with strict ingress/egress rules"
        ],
        correct: 2,
        explanation: {
            correct: "Service mesh with mTLS ensures every service-to-service communication is authenticated and encrypted, implementing true zero-trust.",
            whyWrong: {
                0: "PrivateLink is for AWS service access, not service-to-service within VPC",
                1: "Transit Gateway provides connectivity but not zero-trust authentication",
                3: "Network Firewall provides filtering but not service-level authentication"
            },
            examStrategy: "Zero-trust = authenticate everything. Service mesh (App Mesh) with mTLS for service-to-service security."
        }
    },
    {
        id: 'sec_057',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company discovered cryptomining malware on their EC2 instances and needs to prevent future incidents.",
        question: "Which solution provides the BEST protection against cryptomining malware on EC2?",
        options: [
            "Amazon GuardDuty with cryptocurrency mining detection enabled",
            "AWS Shield Advanced with DDoS protection",
            "AWS WAF with rate limiting rules",
            "Amazon Macie scanning EC2 storage"
        ],
        correct: 0,
        explanation: {
            correct: "GuardDuty specifically detects cryptocurrency mining activity through DNS and network traffic analysis.",
            whyWrong: {
                1: "Shield protects against DDoS, not malware",
                2: "WAF protects web applications, not EC2 malware",
                3: "Macie scans S3 data, not EC2 malware detection"
            },
            examStrategy: "GuardDuty detects threats including cryptomining. Know which service protects against which threat type."
        }
    },
    {
        id: 'sec_058',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "Developers need to retrieve database passwords in their applications without hardcoding credentials.",
        question: "Which AWS service is designed specifically for application credential management?",
        options: [
            "AWS Secrets Manager",
            "AWS Systems Manager Parameter Store",
            "AWS KMS",
            "AWS Certificate Manager"
        ],
        correct: 0,
        explanation: {
            correct: "Secrets Manager is purpose-built for storing and rotating application credentials with native database integration.",
            whyWrong: {
                1: "Parameter Store is more general-purpose, less features for credentials",
                2: "KMS manages encryption keys, not credentials",
                3: "ACM manages SSL/TLS certificates, not passwords"
            },
            examStrategy: "Secrets Manager for credentials with rotation. Parameter Store for configuration. KMS for encryption keys."
        }
    },
    {
        id: 'sec_059',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement data loss prevention (DLP) for their email system integrated with Office 365.",
        question: "How can AWS help implement DLP for Office 365 emails containing sensitive data?",
        options: [
            "Amazon Macie cannot scan Office 365, use native Office 365 DLP",
            "Route emails through SES with Lambda scanning",
            "Use Amazon Comprehend for email content analysis",
            "Implement AWS Network Firewall with DLP rules"
        ],
        correct: 0,
        explanation: {
            correct: "Macie is for S3 data only. Office 365 has its own DLP capabilities that should be used for email.",
            whyWrong: {
                1: "Routing Office 365 emails through SES is complex and may break features",
                2: "Comprehend requires custom integration and doesn't provide DLP features",
                3: "Network Firewall doesn't inspect email content"
            },
            examStrategy: "Know AWS service limitations. Macie = S3 only. Use native services for third-party platforms when appropriate."
        }
    },
    {
        id: 'sec_060',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A military contractor requires air-gapped environments where production data can never flow back to development, but development changes must flow to production.",
        question: "Which architecture ensures unidirectional data flow from development to production?",
        options: [
            "S3 bucket policies with deny rules for production-to-dev copying, CodePipeline for dev-to-prod",
            "Separate AWS accounts with cross-account roles allowing only dev-to-prod actions",
            "AWS DataSync with one-way sync configuration",
            "Different regions with VPC peering and security group rules"
        ],
        correct: 1,
        explanation: {
            correct: "Separate accounts with strictly controlled cross-account roles ensure architectural separation with unidirectional permissions.",
            whyWrong: {
                0: "Bucket policies can be changed, not architecturally enforced",
                2: "DataSync configuration can be modified to bidirectional",
                3: "VPC peering and security groups don't prevent data movement via other methods"
            },
            examStrategy: "Account separation for strong isolation. IAM roles for controlled access. Architecture-level enforcement over configuration."
        }
    },
    {
        id: 'sec_061',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement session management for a web application that prevents session hijacking and fixation attacks.",
        question: "Which session management approach provides the BEST security?",
        options: [
            "JWT tokens with short expiration and refresh token rotation",
            "Server-side sessions in ElastiCache with secure session IDs",
            "Cookie-based sessions with HttpOnly and Secure flags",
            "URL-based session tokens with encryption"
        ],
        correct: 0,
        explanation: {
            correct: "JWT with short expiration and refresh token rotation provides stateless security with automatic token invalidation and renewal.",
            whyWrong: {
                1: "Server-side sessions vulnerable if session ID is compromised",
                2: "Cookie-based sessions susceptible to XSS if not properly implemented",
                3: "URL-based tokens are vulnerable to referrer leakage and logging"
            },
            examStrategy: "JWT for stateless session management. Short expiration limits attack window. Refresh rotation prevents token reuse."
        }
    },
    {
        id: 'sec_062',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to ensure their Lambda functions can only be invoked by their API Gateway and not directly.",
        question: "How should Lambda function invocation be restricted to API Gateway only?",
        options: [
            "Lambda resource-based policy allowing only API Gateway service principal",
            "VPC endpoint for Lambda with security groups",
            "AWS WAF rules on Lambda function URLs",
            "IAM role trust policy for Lambda execution"
        ],
        correct: 0,
        explanation: {
            correct: "Lambda resource-based policies can restrict invocation to specific AWS services like API Gateway using service principals.",
            whyWrong: {
                1: "VPC endpoints don't control Lambda invocation permissions",
                2: "WAF doesn't apply to direct Lambda invocations",
                3: "Execution role trust policy controls what Lambda can do, not who can invoke it"
            },
            examStrategy: "Resource-based policies control who can invoke Lambda. Service principals identify AWS services. Always restrict Lambda invocation sources."
        }
    },
    {
        id: 'sec_063',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement API authentication that supports both mobile apps and web browsers with different security requirements.",
        question: "Which authentication strategy best serves both mobile and web clients?",
        options: [
            "Amazon Cognito with different app clients for mobile and web",
            "API Gateway with single API key for all clients",
            "IAM users with access keys for each client type",
            "Custom authentication with Lambda authorizers"
        ],
        correct: 0,
        explanation: {
            correct: "Cognito supports multiple app clients with different settings, enabling appropriate security for each platform (PKCE for mobile, etc.).",
            whyWrong: {
                1: "Single API key doesn't provide user-level authentication",
                2: "IAM users not appropriate for end-user authentication",
                3: "Custom Lambda authorizers require significant development and maintenance"
            },
            examStrategy: "Cognito for user authentication with multiple client types. Different security requirements = different app clients."
        }
    },
    {
        id: 'sec_064',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial institution needs to implement transaction signing where users must cryptographically sign each transaction with their private key.",
        question: "Which architecture enables client-side transaction signing with non-repudiation?",
        options: [
            "Client-side signing with WebCrypto API, public keys stored in DynamoDB",
            "AWS KMS with customer master keys per user",
            "CloudHSM with user-specific key generation",
            "Cognito with custom authentication challenge"
        ],
        correct: 0,
        explanation: {
            correct: "Client-side signing ensures private keys never leave the user's device, with public keys stored for verification, providing true non-repudiation.",
            whyWrong: {
                1: "KMS doesn't support user-managed private keys",
                2: "CloudHSM keys are server-side, not client-controlled",
                3: "Cognito challenges don't provide transaction-level signing"
            },
            examStrategy: "Client-side cryptography for non-repudiation. Private keys must be user-controlled. Public key infrastructure principles."
        }
    },
    {
        id: 'sec_065',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to detect and prevent data exfiltration attempts from compromised EC2 instances.",
        question: "Which solution provides the BEST detection of data exfiltration attempts?",
        options: [
            "VPC Flow Logs with CloudWatch analysis for unusual data transfers",
            "GuardDuty with threat intelligence feeds",
            "AWS WAF with rate limiting",
            "Security Groups with restrictive egress rules"
        ],
        correct: 1,
        explanation: {
            correct: "GuardDuty uses machine learning and threat intelligence to specifically detect data exfiltration patterns and compromised instances.",
            whyWrong: {
                0: "Flow Logs require manual analysis and pattern definition",
                2: "WAF protects web applications, not EC2 data exfiltration",
                3: "Security Groups are preventive but don't detect exfiltration attempts"
            },
            examStrategy: "GuardDuty for threat detection including data exfiltration. Flow Logs for forensics. Security Groups for prevention."
        }
    },
    {
        id: 'sec_066',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A startup wants to ensure all their EC2 instances are automatically patched with the latest security updates.",
        question: "Which service automates security patching for EC2 instances?",
        options: [
            "AWS Systems Manager Patch Manager",
            "AWS Security Hub",
            "Amazon Inspector",
            "AWS Shield"
        ],
        correct: 0,
        explanation: {
            correct: "Systems Manager Patch Manager automates the patching process for EC2 instances on a defined schedule.",
            whyWrong: {
                1: "Security Hub aggregates findings but doesn't patch",
                2: "Inspector identifies vulnerabilities but doesn't patch",
                3: "Shield provides DDoS protection, not patching"
            },
            examStrategy: "Systems Manager for EC2 management including patching. Patch Manager for automated updates. Inspector finds vulnerabilities."
        }
    },
    {
        id: 'sec_067',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure parameter validation for all API inputs to prevent injection attacks.",
        question: "Which approach provides the MOST comprehensive input validation for APIs?",
        options: [
            "API Gateway request validation with JSON schemas and AWS WAF with SQL injection rules",
            "Lambda function input validation only",
            "CloudFront with custom headers",
            "Application Load Balancer with rule conditions"
        ],
        correct: 0,
        explanation: {
            correct: "API Gateway validates structure via JSON schemas while WAF provides pattern-based validation for injection attacks, providing defense in depth.",
            whyWrong: {
                1: "Lambda validation alone misses the API layer protection",
                2: "CloudFront headers don't provide input validation",
                3: "ALB rules are for routing, not comprehensive input validation"
            },
            examStrategy: "Layer your input validation: API Gateway for structure, WAF for patterns, application for business logic."
        }
    },
    {
        id: 'sec_068',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A healthcare provider needs to implement break-glass access procedures for emergency access to patient records with full audit trail.",
        question: "Which solution provides auditable emergency access with approval workflow?",
        options: [
            "AWS SSO with temporary permission sets activated through AWS Service Catalog",
            "IAM roles with MFA and CloudTrail logging",
            "Direct root account access with MFA",
            "Pre-created high-privilege IAM users with disabled console access"
        ],
        correct: 0,
        explanation: {
            correct: "SSO with Service Catalog provides controlled, time-limited emergency access with approval workflow and complete audit trail.",
            whyWrong: {
                1: "IAM roles lack built-in approval workflow",
                2: "Root account access should never be used for break-glass",
                3: "Pre-created users are security risks and lack approval workflow"
            },
            examStrategy: "Break-glass access needs: approval workflow, time limits, full audit trail. Service Catalog for controlled elevated access."
        }
    },
    {
        id: 'sec_069',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their containerized applications don't run with root privileges and have minimal permissions.",
        question: "Which solution enforces least-privilege containers in ECS?",
        options: [
            "ECS task definitions with user ID specification and read-only root filesystem",
            "IAM roles for tasks with minimal permissions",
            "Security Groups with restrictive rules",
            "AWS WAF protecting container endpoints"
        ],
        correct: 0,
        explanation: {
            correct: "Task definitions can specify non-root users and read-only filesystems, enforcing least-privilege at the container level.",
            whyWrong: {
                1: "IAM roles control AWS API access, not container runtime privileges",
                2: "Security Groups control network access, not container privileges",
                3: "WAF protects web traffic, not container runtime security"
            },
            examStrategy: "Container security: non-root users, read-only filesystems, minimal Linux capabilities. Task definition enforces runtime security."
        }
    },
    {
        id: 'sec_070',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to encrypt all data in their DynamoDB tables without application changes.",
        question: "How can DynamoDB encryption be enabled with zero application impact?",
        options: [
            "Enable encryption at rest in DynamoDB table settings",
            "Implement client-side encryption in the application",
            "Use VPC endpoints with encryption",
            "Configure AWS KMS with custom keys"
        ],
        correct: 0,
        explanation: {
            correct: "DynamoDB encryption at rest can be enabled transparently without any application code changes.",
            whyWrong: {
                1: "Client-side encryption requires application changes",
                2: "VPC endpoints provide network security, not encryption at rest",
                3: "KMS configuration alone doesn't enable DynamoDB encryption"
            },
            examStrategy: "DynamoDB encryption at rest is transparent to applications. Enable in table settings. No code changes required."
        }
    },
    {
        id: 'sec_071',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company discovered that developers have been committing AWS credentials to their Git repositories.",
        question: "Which solution prevents and detects credential exposure in code repositories?",
        options: [
            "Amazon CodeGuru Reviewer with secrets detection and git pre-commit hooks",
            "AWS CloudTrail with event monitoring",
            "IAM Access Analyzer only",
            "Manual code reviews before deployment"
        ],
        correct: 0,
        explanation: {
            correct: "CodeGuru Reviewer automatically detects secrets in code, while pre-commit hooks prevent credentials from being committed.",
            whyWrong: {
                1: "CloudTrail logs API usage but doesn't scan code repositories",
                2: "Access Analyzer reviews policies, not code repositories",
                3: "Manual reviews are error-prone and don't prevent commits"
            },
            examStrategy: "CodeGuru for automated code scanning. Pre-commit hooks for prevention. Never store credentials in code."
        }
    },
    {
        id: 'sec_072',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A bank needs to implement transaction fraud detection that can identify anomalies in real-time across millions of transactions per day.",
        question: "Which architecture provides real-time fraud detection at scale?",
        options: [
            "Kinesis Data Analytics with Amazon Fraud Detector for ML-based detection",
            "Lambda functions with rule-based checking",
            "Batch processing with EMR and scheduled analysis",
            "RDS triggers with stored procedures"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis Analytics processes streaming data in real-time while Fraud Detector provides ML-based anomaly detection specifically for fraud.",
            whyWrong: {
                1: "Lambda rule-based checking lacks ML capabilities and may timeout",
                2: "Batch processing isn't real-time",
                3: "RDS triggers don't scale to millions of transactions efficiently"
            },
            examStrategy: "Amazon Fraud Detector for fraud-specific ML. Kinesis for real-time streaming. Purpose-built services over custom solutions."
        }
    },
    {
        id: 'sec_073',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure API versioning where old API versions can be deprecated without breaking existing clients.",
        question: "Which API Gateway feature enables secure API versioning with controlled deprecation?",
        options: [
            "API Gateway stages with different versions and usage plans for access control",
            "Lambda function versioning only",
            "Route 53 weighted routing between versions",
            "CloudFront behaviors for different paths"
        ],
        correct: 0,
        explanation: {
            correct: "API Gateway stages allow multiple versions to coexist with usage plans controlling access and throttling per version.",
            whyWrong: {
                1: "Lambda versioning alone doesn't provide API-level version management",
                2: "Route 53 doesn't provide API-specific versioning features",
                3: "CloudFront behaviors don't provide API versioning capabilities"
            },
            examStrategy: "API Gateway stages for versioning. Usage plans for access control and throttling. Gradual deprecation strategy."
        }
    },
    {
        id: 'sec_074',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to ensure that all EBS volumes are encrypted when attached to EC2 instances.",
        question: "How can EBS encryption be enforced across the organization?",
        options: [
            "Enable EBS encryption by default in account settings",
            "Use CloudFormation templates with encryption specified",
            "Configure EC2 launch templates with encryption",
            "Manually encrypt each volume after creation"
        ],
        correct: 0,
        explanation: {
            correct: "EBS encryption by default ensures all new EBS volumes are automatically encrypted without additional configuration.",
            whyWrong: {
                1: "CloudFormation only affects resources created through templates",
                2: "Launch templates only affect instances using those templates",
                3: "Manual encryption is error-prone and not enforceable"
            },
            examStrategy: "Account-level settings for organization-wide enforcement. EBS encryption by default is the simplest solution."
        }
    },
    {
        id: 'sec_075',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure multi-party computation where multiple parties can compute on shared data without revealing their inputs.",
        question: "Which AWS service enables secure multi-party computation?",
        options: [
            "AWS Clean Rooms for collaborative data analysis without sharing raw data",
            "AWS Lake Formation with fine-grained permissions",
            "Amazon DataZone with data mesh architecture",
            "AWS Glue DataBrew with data masking"
        ],
        correct: 0,
        explanation: {
            correct: "AWS Clean Rooms enables multiple parties to analyze combined datasets without sharing underlying data, perfect for secure multi-party computation.",
            whyWrong: {
                1: "Lake Formation provides access control but requires data sharing",
                2: "DataZone facilitates data sharing, not privacy-preserving computation",
                3: "DataBrew transforms data but doesn't enable multi-party computation"
            },
            examStrategy: "AWS Clean Rooms for privacy-preserving collaboration. Allows computation without data exposure. Think data collaboration requirements."
        }
    },
    {
        id: 'sec_076',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A government agency requires quantum-resistant encryption for long-term data storage, anticipating future quantum computing threats.",
        question: "Which encryption approach provides the BEST quantum resistance for long-term storage?",
        options: [
            "AWS KMS with multiple encryption layers using different algorithms",
            "Client-side encryption with post-quantum cryptography libraries",
            "S3 default encryption with regular key rotation",
            "CloudHSM with FIPS-validated algorithms"
        ],
        correct: 1,
        explanation: {
            correct: "Client-side encryption with post-quantum cryptography libraries provides defense against future quantum attacks using quantum-resistant algorithms.",
            whyWrong: {
                0: "Current KMS algorithms aren't specifically quantum-resistant",
                2: "S3 default encryption uses current algorithms vulnerable to future quantum attacks",
                3: "CloudHSM FIPS algorithms aren't necessarily quantum-resistant"
            },
            examStrategy: "Quantum resistance requires post-quantum cryptography. Client-side control for algorithm choice. Consider future threat landscape."
        }
    },
    {
        id: 'sec_077',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement zero-knowledge proof authentication where users can prove their identity without revealing credentials.",
        question: "Which authentication approach best approximates zero-knowledge proof concepts?",
        options: [
            "FIDO2/WebAuthn passwordless authentication with biometrics",
            "AWS Cognito with username/password",
            "IAM roles with temporary credentials",
            "API keys with request signing"
        ],
        correct: 0,
        explanation: {
            correct: "FIDO2/WebAuthn uses public key cryptography where authentication occurs without transmitting actual credentials, closest to zero-knowledge concepts.",
            whyWrong: {
                1: "Username/password transmits actual credentials",
                2: "IAM roles still involve credential exchange",
                3: "API keys are credentials that must be transmitted"
            },
            examStrategy: "Passwordless authentication for enhanced security. FIDO2/WebAuthn for phishing resistance. Modern authentication methods."
        }
    },
    {
        id: 'sec_078',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to automatically rotate their RDS database passwords every 30 days.",
        question: "Which service provides automatic password rotation for RDS?",
        options: [
            "AWS Secrets Manager with automatic rotation",
            "AWS Systems Manager Parameter Store",
            "AWS KMS key rotation",
            "RDS built-in password management"
        ],
        correct: 0,
        explanation: {
            correct: "Secrets Manager provides built-in automatic rotation for RDS passwords with Lambda functions handling the rotation logic.",
            whyWrong: {
                1: "Parameter Store doesn't have automatic rotation features",
                2: "KMS rotates encryption keys, not passwords",
                3: "RDS doesn't have built-in automatic password rotation"
            },
            examStrategy: "Secrets Manager for automatic credential rotation. Built-in support for RDS, Redshift, DocumentDB."
        }
    },
    {
        id: 'sec_079',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure code signing for Lambda functions to ensure only authorized code is deployed.",
        question: "Which solution provides code signing for Lambda deployments?",
        options: [
            "AWS Signer with Lambda code signing configuration",
            "AWS CodeCommit with branch protection",
            "AWS CodePipeline with manual approval",
            "Lambda layers with version control"
        ],
        correct: 0,
        explanation: {
            correct: "AWS Signer provides code signing for Lambda functions, ensuring only trusted code is deployed to Lambda.",
            whyWrong: {
                1: "CodeCommit branch protection doesn't provide code signing",
                2: "Manual approval doesn't cryptographically verify code integrity",
                3: "Lambda layers don't provide code signing capabilities"
            },
            examStrategy: "AWS Signer for code signing. Cryptographic verification of code integrity. Prevent unauthorized code deployment."
        }
    },
    {
        id: 'sec_080',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial institution needs to implement a complete audit trail that proves no unauthorized changes occurred to their compliance data over 10 years.",
        question: "Which architecture provides cryptographically verifiable audit trails?",
        options: [
            "Amazon QLDB with cryptographic verification APIs",
            "CloudTrail with S3 Object Lock and digest files",
            "RDS with triggers and audit tables",
            "DynamoDB Streams with Lambda processing"
        ],
        correct: 0,
        explanation: {
            correct: "QLDB provides an immutable ledger with built-in cryptographic verification, proving no unauthorized changes occurred.",
            whyWrong: {
                1: "CloudTrail provides logs but not cryptographic proof of data integrity",
                2: "RDS triggers can be modified, breaking audit trail integrity",
                3: "DynamoDB Streams don't provide cryptographic verification"
            },
            examStrategy: "QLDB for immutable, cryptographically verifiable ledgers. Built-in proof of data integrity. Compliance-grade audit trails."
        }
    },
    {
        id: 'sec_081',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement privacy-preserving analytics where data analysts can query aggregate data but cannot access individual records.",
        question: "Which solution enables privacy-preserving analytics on sensitive data?",
        options: [
            "AWS Lake Formation with column-level security and data filters",
            "S3 with bucket policies restricting object access",
            "Athena with row-level security",
            "Redshift with user-defined functions"
        ],
        correct: 0,
        explanation: {
            correct: "Lake Formation provides fine-grained access control with column-level security and data filters to restrict access to sensitive data.",
            whyWrong: {
                1: "S3 bucket policies work at object level, not row/column level",
                2: "Athena doesn't natively provide row-level security",
                3: "Redshift UDFs don't provide privacy-preserving features"
            },
            examStrategy: "Lake Formation for fine-grained data access control. Column and row level security. Central data governance."
        }
    },
    {
        id: 'sec_082',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A startup wants to ensure their application logs don't contain sensitive customer information.",
        question: "Which approach BEST prevents sensitive data from appearing in CloudWatch Logs?",
        options: [
            "Application-level log filtering before sending to CloudWatch",
            "CloudWatch Logs Insights queries to filter data",
            "S3 lifecycle policies to delete old logs",
            "KMS encryption of log groups"
        ],
        correct: 0,
        explanation: {
            correct: "Filtering sensitive data at the application level prevents it from ever reaching CloudWatch Logs.",
            whyWrong: {
                1: "Insights queries retrieve data but don't prevent storage",
                2: "Lifecycle policies delete logs but don't prevent sensitive data logging",
                3: "Encryption protects data but doesn't prevent sensitive data inclusion"
            },
            examStrategy: "Prevent sensitive data logging at the source. Application-level controls are most effective. Never log PII/sensitive data."
        }
    },
    {
        id: 'sec_083',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure secrets injection for containerized applications without embedding secrets in images.",
        question: "Which solution provides secure runtime secret injection for containers?",
        options: [
            "ECS with Secrets Manager integration in task definitions",
            "Building secrets into container images with encryption",
            "Environment variables in ECS task definitions",
            "S3 bucket with encrypted secrets files"
        ],
        correct: 0,
        explanation: {
            correct: "ECS integrates with Secrets Manager to inject secrets at runtime without storing them in images or task definitions.",
            whyWrong: {
                1: "Secrets in images are insecure and difficult to rotate",
                2: "Environment variables in task definitions are visible in console/API",
                3: "S3 requires custom implementation and additional permissions"
            },
            examStrategy: "Never embed secrets in container images. ECS Secrets Manager integration for runtime injection. Separation of secrets from code."
        }
    },
    {
        id: 'sec_084',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company needs to implement homomorphic encryption allowing computation on encrypted data without decryption for privacy compliance.",
        question: "How can AWS support homomorphic encryption requirements?",
        options: [
            "Custom implementation using EC2 with specialized libraries, as AWS doesn't natively support homomorphic encryption",
            "AWS KMS with custom key policies",
            "S3 client-side encryption with computation",
            "Lambda with encrypted environment variables"
        ],
        correct: 0,
        explanation: {
            correct: "Homomorphic encryption requires specialized libraries and custom implementation; AWS doesn't provide native homomorphic encryption services.",
            whyWrong: {
                1: "KMS doesn't support homomorphic encryption",
                2: "S3 client-side encryption doesn't enable computation on encrypted data",
                3: "Lambda encrypted variables must be decrypted for use"
            },
            examStrategy: "Know AWS service limitations. Homomorphic encryption requires custom implementation. Some security features need third-party solutions."
        }
    },
    {
        id: 'sec_085',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement API rate limiting per customer to prevent abuse while allowing legitimate traffic bursts.",
        question: "Which API Gateway feature provides flexible per-customer rate limiting?",
        options: [
            "Usage plans with API keys and burst limits",
            "AWS WAF with rate-based rules",
            "Lambda authorizers with custom logic",
            "CloudFront with cache behaviors"
        ],
        correct: 0,
        explanation: {
            correct: "Usage plans with API keys provide per-customer throttling with configurable rate and burst limits.",
            whyWrong: {
                1: "WAF rate limits are IP-based, not customer-based",
                2: "Lambda authorizers add latency and complexity for simple rate limiting",
                3: "CloudFront caching doesn't provide rate limiting"
            },
            examStrategy: "API Gateway usage plans for customer-specific limits. Burst capacity for legitimate spikes. API keys for customer identification."
        }
    },
    {
        id: 'sec_086',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company discovered unauthorized S3 bucket access and needs to immediately revoke all existing access.",
        question: "What is the FASTEST way to revoke all S3 bucket access?",
        options: [
            "Add an explicit deny-all bucket policy",
            "Delete all IAM users and roles",
            "Enable S3 Block Public Access",
            "Rotate all access keys"
        ],
        correct: 0,
        explanation: {
            correct: "An explicit deny-all bucket policy immediately overrides all other permissions, blocking access instantly.",
            whyWrong: {
                1: "Deleting IAM entities is destructive and may not cover all access paths",
                2: "Block Public Access only affects public access, not authenticated access",
                3: "Key rotation takes time and might miss some access patterns"
            },
            examStrategy: "Explicit deny overrides allow. Bucket policies for immediate S3 access control. Quick incident response tactics."
        }
    },
    {
        id: 'sec_087',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement certificate pinning for their mobile application to prevent man-in-the-middle attacks.",
        question: "How should certificate pinning be implemented for APIs hosted on AWS?",
        options: [
            "Pin the intermediate CA certificate in mobile app with backup pins",
            "Pin the leaf certificate and update app with each renewal",
            "Use AWS Certificate Manager with automatic rotation",
            "Implement mutual TLS with client certificates"
        ],
        correct: 0,
        explanation: {
            correct: "Pinning intermediate CA certificates provides security while allowing leaf certificate rotation without app updates.",
            whyWrong: {
                1: "Pinning leaf certificates requires app updates with each renewal",
                2: "ACM handles server certificates, not client-side pinning",
                3: "mTLS is different from certificate pinning"
            },
            examStrategy: "Certificate pinning at intermediate CA level for flexibility. Balance security with operational needs. Mobile app update cycles."
        }
    },
    {
        id: 'sec_088',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A blockchain company needs to secure private keys for millions of users with hardware-level security and user-controlled access.",
        question: "Which architecture provides user-controlled hardware-secured keys at scale?",
        options: [
            "Client-side hardware security modules (mobile/computer TPM) with cloud backup of encrypted keys",
            "AWS CloudHSM with key isolation per user",
            "AWS KMS with customer managed keys",
            "AWS Nitro Enclaves with key generation"
        ],
        correct: 0,
        explanation: {
            correct: "Client-side hardware (TPM/Secure Enclave) ensures users control their keys with hardware security, cloud stores only encrypted backups.",
            whyWrong: {
                1: "CloudHSM doesn't scale cost-effectively to millions of users",
                2: "KMS doesn't provide user-controlled keys",
                3: "Nitro Enclaves are server-side, not user-controlled"
            },
            examStrategy: "User-controlled keys require client-side management. Hardware security at user device level. Cloud for encrypted backup only."
        }
    },
    {
        id: 'sec_089',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement dynamic data masking where different users see different levels of data detail based on their roles.",
        question: "Which solution provides dynamic data masking based on user roles?",
        options: [
            "AWS Lake Formation with data filters and column-level permissions",
            "Lambda function modifying query results based on user",
            "Multiple database views with different masking levels",
            "API Gateway with response transformation"
        ],
        correct: 0,
        explanation: {
            correct: "Lake Formation provides dynamic data filtering and masking based on user permissions without duplicating data.",
            whyWrong: {
                1: "Lambda adds latency and complexity for every query",
                2: "Multiple views require maintenance and storage overhead",
                3: "API Gateway transformation is complex for dynamic masking"
            },
            examStrategy: "Lake Formation for centralized data governance. Dynamic filtering without data duplication. Role-based data access."
        }
    },
    {
        id: 'sec_090',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to prevent accidental deletion of critical EC2 instances.",
        question: "Which feature prevents accidental EC2 instance termination?",
        options: [
            "Enable termination protection on instances",
            "Use dedicated hosts",
            "Configure deletion protection in security groups",
            "Enable EBS volume encryption"
        ],
        correct: 0,
        explanation: {
            correct: "Termination protection prevents instances from being terminated through the console, CLI, or API when enabled.",
            whyWrong: {
                1: "Dedicated hosts don't prevent termination",
                2: "Security groups don't have deletion protection features",
                3: "EBS encryption doesn't prevent instance termination"
            },
            examStrategy: "Termination protection for critical instances. Simple but effective protection against accidents. Enable for production resources."
        }
    },
    {
        id: 'sec_091',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement API authentication that works offline and doesn't require constant connectivity to authentication servers.",
        question: "Which authentication method supports offline validation?",
        options: [
            "JWT tokens with signature verification using embedded public keys",
            "API Gateway with API keys",
            "OAuth 2.0 with token introspection",
            "SAML assertions with IdP validation"
        ],
        correct: 0,
        explanation: {
            correct: "JWT tokens can be validated offline using embedded public keys for signature verification without authentication server calls.",
            whyWrong: {
                1: "API keys require online validation through API Gateway",
                2: "OAuth token introspection requires online IdP connectivity",
                3: "SAML typically requires online validation with IdP"
            },
            examStrategy: "JWT for offline/distributed validation. Self-contained tokens with claims. Public key cryptography for verification."
        }
    },
    {
        id: 'sec_092',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company needs to implement secure multicast encryption where one sender can encrypt data for multiple specific recipients efficiently.",
        question: "Which encryption approach enables efficient secure multicast?",
        options: [
            "Attribute-based encryption with policy-defined recipient groups",
            "Individual encryption for each recipient",
            "Shared symmetric key for all recipients",
            "AWS KMS with grant tokens"
        ],
        correct: 0,
        explanation: {
            correct: "Attribute-based encryption allows encrypting once for multiple recipients based on attributes/policies, efficient for multicast.",
            whyWrong: {
                1: "Individual encryption doesn't scale for many recipients",
                2: "Shared keys compromise security if one recipient is compromised",
                3: "KMS grants are for access control, not multicast encryption"
            },
            examStrategy: "Advanced encryption schemes for specific use cases. Attribute-based encryption for group encryption. Balance security with efficiency."
        }
    },
    {
        id: 'sec_093',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to detect and prevent insider threats from employees with legitimate access to sensitive data.",
        question: "Which solution BEST detects anomalous insider activity?",
        options: [
            "Amazon Macie with anomaly detection and CloudTrail analysis for unusual access patterns",
            "VPC Flow Logs with traffic analysis",
            "AWS Config with compliance rules",
            "GuardDuty with threat intelligence"
        ],
        correct: 0,
        explanation: {
            correct: "Macie detects unusual data access patterns in S3 while CloudTrail analysis reveals abnormal API usage, identifying insider threats.",
            whyWrong: {
                1: "Flow Logs show network traffic, not data access patterns",
                2: "Config checks compliance, not behavioral anomalies",
                3: "GuardDuty focuses on external threats more than insider activity"
            },
            examStrategy: "Combine services for insider threat detection. Behavioral analysis over rule-based detection. Monitor data access patterns."
        }
    },
    {
        id: 'sec_094',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to ensure all CloudFormation stacks follow security best practices before deployment.",
        question: "Which tool validates CloudFormation templates for security issues?",
        options: [
            "AWS CloudFormation Guard (cfn-guard)",
            "AWS CloudTrail",
            "AWS Inspector",
            "AWS Shield"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFormation Guard validates templates against security policies before deployment, preventing misconfigurations.",
            whyWrong: {
                1: "CloudTrail logs API calls, doesn't validate templates",
                2: "Inspector assesses running resources, not templates",
                3: "Shield provides DDoS protection, not template validation"
            },
            examStrategy: "cfn-guard for IaC security validation. Shift-left security approach. Prevent misconfigurations before deployment."
        }
    },
    {
        id: 'sec_095',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement secure disaster recovery where the DR site cannot access production data unless explicitly activated.",
        question: "Which architecture ensures DR isolation until activation?",
        options: [
            "Separate AWS accounts with cross-account roles that require break-glass activation",
            "Different regions with continuous replication",
            "Different VPCs with peering connections",
            "Same account with different IAM roles"
        ],
        correct: 0,
        explanation: {
            correct: "Separate accounts with break-glass activation ensure complete isolation until DR is explicitly needed, preventing accidental access.",
            whyWrong: {
                1: "Continuous replication means DR always has data access",
                2: "VPC peering doesn't provide sufficient access isolation",
                3: "Same account makes isolation harder to enforce"
            },
            examStrategy: "Account separation for strong isolation. Break-glass procedures for emergency access. DR isolation until needed."
        }
    },
    {
        id: 'sec_096',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company needs to implement secure collaborative machine learning where multiple parties train models on combined data without sharing raw datasets.",
        question: "Which approach enables privacy-preserving collaborative ML?",
        options: [
            "Federated learning with model updates instead of data sharing",
            "Centralized data lake with access controls",
            "Data masking before sharing",
            "Separate models trained independently"
        ],
        correct: 0,
        explanation: {
            correct: "Federated learning trains models on distributed data, sharing only model updates, preserving privacy of raw data.",
            whyWrong: {
                1: "Centralized data lake requires data sharing",
                2: "Masking may lose important features for ML",
                3: "Separate models don't benefit from combined data insights"
            },
            examStrategy: "Federated learning for privacy-preserving ML. AWS doesn't have native federated learning - requires custom implementation."
        }
    },
    {
        id: 'sec_097',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their Lambda functions cannot access the internet while still accessing AWS services.",
        question: "Which configuration restricts Lambda internet access while maintaining AWS service connectivity?",
        options: [
            "Deploy Lambda in VPC with VPC endpoints for AWS services and no internet gateway",
            "Use Lambda resource policies to block internet access",
            "Configure Lambda with security groups blocking outbound traffic",
            "Enable Lambda private mode in function configuration"
        ],
        correct: 0,
        explanation: {
            correct: "VPC deployment without internet gateway blocks internet access, while VPC endpoints enable AWS service communication.",
            whyWrong: {
                1: "Resource policies control invocation, not network access",
                2: "Security groups alone can't block all internet while allowing AWS services",
                3: "Lambda doesn't have a 'private mode' setting"
            },
            examStrategy: "VPC without IGW for internet isolation. VPC endpoints for AWS service access. Network isolation patterns."
        }
    },
    {
        id: 'sec_098',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to track all changes made to their security groups for compliance auditing.",
        question: "Which service automatically tracks security group changes?",
        options: [
            "AWS CloudTrail",
            "VPC Flow Logs",
            "AWS Shield",
            "Amazon Inspector"
        ],
        correct: 0,
        explanation: {
            correct: "CloudTrail automatically logs all API calls including security group modifications with full details.",
            whyWrong: {
                1: "Flow Logs track network traffic, not configuration changes",
                2: "Shield provides DDoS protection, not change tracking",
                3: "Inspector assesses vulnerabilities, not configuration changes"
            },
            examStrategy: "CloudTrail for API and configuration change tracking. Automatic logging of all AWS API calls. Compliance audit trail."
        }
    },
    {
        id: 'sec_099',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to implement data tokenization where sensitive data is replaced with tokens that have no exploitable value.",
        question: "Which approach provides true data tokenization?",
        options: [
            "Store tokens in application with mapping table in separate secured database",
            "Use encryption with the key stored alongside data",
            "Hash sensitive data with salt",
            "Base64 encode sensitive data"
        ],
        correct: 0,
        explanation: {
            correct: "True tokenization uses random tokens with mapping stored separately, making tokens useless without the mapping database.",
            whyWrong: {
                1: "Encryption with nearby keys defeats the purpose",
                2: "Hashing may be reversible with rainbow tables",
                3: "Base64 is encoding, not security"
            },
            examStrategy: "Tokenization vs encryption: tokens have no mathematical relationship to original data. Separate token storage from data."
        }
    },
    {
        id: 'sec_100',
        domain: "Domain 1: Design Secure Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company needs to implement secure software supply chain validation ensuring all deployed code comes from verified sources.",
        question: "Which architecture provides comprehensive software supply chain security?",
        options: [
            "CodePipeline with CodeGuru security scanning, AWS Signer, and Lambda code signing configuration",
            "Manual code reviews before deployment",
            "GitHub integration with branch protection",
            "Container scanning in ECR"
        ],
        correct: 0,
        explanation: {
            correct: "Combination of automated security scanning, code signing, and signature verification ensures end-to-end supply chain security.",
            whyWrong: {
                1: "Manual reviews don't provide cryptographic verification",
                2: "Branch protection doesn't verify code integrity through deployment",
                3: "Container scanning alone doesn't verify source authenticity"
            },
            examStrategy: "Multiple layers for supply chain security. Code signing for integrity. Automated scanning for vulnerabilities. End-to-end verification."
        }
    }
],

    // Domain 2: Design Resilient Architectures (130 questions - 26%)
    resilience: [
        {
            id: 'res_001',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company runs a critical web application on EC2 instances behind an Application Load Balancer. They need to ensure the application remains available during instance failures and can handle traffic spikes.",
            question: "Which combination provides the HIGHEST availability and scalability?",
            options: [
                "Auto Scaling group across multiple AZs with target tracking scaling policies",
                "EC2 instances in a single AZ with scheduled scaling and EBS snapshots",
                "Auto Scaling group in one AZ with predictive scaling enabled",
                "Manual scaling across AZs with CloudWatch alarms for notifications"
            ],
            correct: 0,
            explanation: {
                correct: "Multi-AZ Auto Scaling with target tracking automatically maintains availability during failures and scales based on actual demand metrics.",
                whyWrong: {
                    1: "Single AZ deployment has no resilience to AZ failures",
                    2: "Single AZ means no AZ-level fault tolerance despite predictive scaling",
                    3: "Manual scaling is slow to respond and error-prone"
                },
                examStrategy: "Multi-AZ deployment is fundamental for high availability. Auto Scaling provides both resilience and scalability."
            }
        },
        {
            id: 'res_002',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A global e-commerce platform needs to maintain sub-second database read performance across three continents while ensuring zero data loss in case of regional failures.",
            question: "Which database architecture provides global read performance with zero data loss capability?",
            options: [
                "Amazon Aurora Global Database with up to 5 secondary regions",
                "Amazon RDS Multi-AZ with read replicas in each region",
                "Amazon DynamoDB Global Tables with multi-region replication",
                "Amazon RDS with cross-region automated backups"
            ],
            correct: 0,
            explanation: {
                correct: "Aurora Global Database provides <1 second replication to secondary regions and allows promotion with zero data loss using backtrack.",
                whyWrong: {
                    1: "RDS read replicas have asynchronous replication with potential data loss",
                    2: "DynamoDB Global Tables have eventual consistency and potential conflicts",
                    3: "Backups don't provide real-time replication or fast failover"
                },
                examStrategy: "Aurora Global Database is the premium solution for global databases with RPO near zero. DynamoDB Global Tables for NoSQL needs."
            }
        },
        {
            id: 'res_003',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A media company needs to ensure their video streaming application can handle millions of concurrent users with automatic failover if the primary region fails.",
            question: "Which architecture provides the BEST resilience for video streaming at scale?",
            options: [
                "CloudFront with S3 origins in multiple regions and Origin Failover",
                "EC2 instances with Elastic IPs and Route 53 health checks",
                "Application Load Balancer with EC2 Auto Scaling in one region",
                "AWS Global Accelerator with Network Load Balancers"
            ],
            correct: 0,
            explanation: {
                correct: "CloudFront with S3 multi-region origins and Origin Failover provides automatic failover and global edge caching for video content.",
                whyWrong: {
                    1: "EC2-based streaming doesn't scale to millions of users cost-effectively",
                    2: "Single region deployment has no regional failure protection",
                    3: "Global Accelerator is for dynamic content, not optimal for video streaming"
                },
                examStrategy: "CloudFront + S3 is the go-to architecture for static content and video streaming at scale. Origin Failover enables multi-region resilience."
            }
        },
        {
            id: 'res_004',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company needs to ensure their RDS database remains available during maintenance windows and instance failures.",
            question: "Which RDS configuration provides the BEST availability?",
            options: [
                "RDS Single-AZ with automated backups",
                "RDS Multi-AZ with automatic failover",
                "RDS with read replicas in the same AZ",
                "RDS with manual snapshots every hour"
            ],
            correct: 1,
            explanation: {
                correct: "RDS Multi-AZ provides synchronous replication and automatic failover during failures or maintenance, minimizing downtime.",
                whyWrong: {
                    0: "Single-AZ has downtime during maintenance and no automatic failover",
                    2: "Read replicas in same AZ don't provide AZ-level failure protection",
                    3: "Manual snapshots don't provide high availability or automatic failover"
                },
                examStrategy: "RDS Multi-AZ = High Availability. Read Replicas = Read Scaling. Always choose Multi-AZ for availability requirements."
            }
        },
        {
            id: 'res_005',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A SaaS application needs to process customer uploads asynchronously while ensuring no message loss even if processing components fail.",
            question: "Which messaging architecture provides the HIGHEST durability and resilience?",
            options: [
                "Amazon SQS Standard queue with Dead Letter Queue configuration",
                "Amazon SNS with email subscriptions for notifications",
                "Amazon Kinesis Data Streams with multiple consumers",
                "Amazon MQ with persistent message storage"
            ],
            correct: 0,
            explanation: {
                correct: "SQS with DLQ provides message durability across multiple AZs and automatic handling of failed messages for later processing.",
                whyWrong: {
                    1: "SNS is for pub/sub notifications, not durable message queuing",
                    2: "Kinesis is for real-time streaming, not async message processing",
                    3: "Amazon MQ requires more management and isn't as integrated with AWS services"
                },
                examStrategy: "SQS for async processing and decoupling. SNS for notifications. Kinesis for real-time streaming. Know the use cases."
            }
        },
        {
            id: 'res_006',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A financial trading platform requires exactly-once message processing with strict ordering of trades per customer account across distributed systems.",
            question: "Which messaging solution ensures both ordering and exactly-once processing?",
            options: [
                "SQS FIFO queue with message deduplication enabled",
                "SQS Standard queue with application-level deduplication",
                "SNS with SQS Standard queue subscriptions",
                "Kinesis Data Streams with checkpointing"
            ],
            correct: 0,
            explanation: {
                correct: "SQS FIFO provides strict ordering and built-in deduplication for exactly-once processing within the deduplication interval.",
                whyWrong: {
                    1: "Standard queues don't guarantee ordering",
                    2: "SNS to SQS Standard doesn't maintain message ordering",
                    3: "Kinesis requires complex application logic for exactly-once processing"
                },
                examStrategy: "SQS FIFO = ordering + exactly-once. Standard SQS = at-least-once, best-effort ordering. FIFO for financial/critical transactions."
            }
        },
        {
            id: 'res_007',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to implement disaster recovery for their business-critical application with RTO of 1 hour and RPO of 15 minutes.",
            question: "Which disaster recovery strategy meets these requirements MOST cost-effectively?",
            options: [
                "Backup and restore with automated recovery procedures",
                "Pilot light with core infrastructure always running",
                "Warm standby with scaled-down version running",
                "Multi-site active-active configuration"
            ],
            correct: 2,
            explanation: {
                correct: "Warm standby keeps a scaled-down version running, allowing quick scale-up within 1 hour RTO while continuous replication meets 15-minute RPO.",
                whyWrong: {
                    0: "Backup and restore typically can't meet 1-hour RTO",
                    1: "Pilot light requires spinning up resources, challenging for 1-hour RTO",
                    3: "Active-active is more expensive than necessary for these requirements"
                },
                examStrategy: "Match DR strategy to RTO/RPO: Backup (hours/days), Pilot Light (hours), Warm Standby (minutes), Active-Active (real-time)."
            }
        },
        {
            id: 'res_008',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A startup needs to ensure their static website remains available even if their primary S3 bucket fails.",
            question: "What is the SIMPLEST way to provide high availability for a static website?",
            options: [
                "S3 with Cross-Region Replication to another bucket",
                "S3 with CloudFront distribution",
                "S3 with versioning and lifecycle policies",
                "Multiple S3 buckets with Route 53 failover routing"
            ],
            correct: 1,
            explanation: {
                correct: "CloudFront caches content at edge locations, providing availability even if the origin S3 bucket is temporarily unavailable.",
                whyWrong: {
                    0: "CRR requires additional configuration and doesn't provide automatic failover",
                    2: "Versioning doesn't provide high availability",
                    3: "More complex setup than necessary for static content"
                },
                examStrategy: "CloudFront provides both performance and availability for static content. It's the simplest HA solution for S3 websites."
            }
        },
        {
            id: 'res_009',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An IoT platform needs to ingest millions of sensor readings per second while ensuring data is not lost during processing failures.",
            question: "Which data ingestion solution provides the BEST durability and scalability?",
            options: [
                "Amazon Kinesis Data Streams with data retention period configured",
                "Amazon API Gateway with Lambda functions",
                "Amazon SQS with maximum message retention",
                "Direct writes to Amazon S3 using IoT Core"
            ],
            correct: 0,
            explanation: {
                correct: "Kinesis Data Streams can handle millions of records per second with configurable retention (up to 365 days) for replay capability.",
                whyWrong: {
                    1: "API Gateway has throttling limits not suitable for millions of requests per second",
                    2: "SQS has lower throughput limits for this volume",
                    3: "Direct S3 writes don't provide stream processing capabilities"
                },
                examStrategy: "Kinesis for high-volume streaming data. SQS for application decoupling. Know the throughput characteristics."
            }
        },
        {
            id: 'res_010',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A healthcare platform requires 99.99% availability for their API serving patient data. The application runs in us-east-1 and needs protection against both AZ and region failures.",
            question: "Which architecture provides 99.99% availability MOST effectively?",
            options: [
                "Multi-AZ deployment in us-east-1 with Auto Scaling and RDS Multi-AZ",
                "Active-passive setup with Route 53 failover between two regions",
                "Active-active deployment across two regions with Route 53 weighted routing",
                "Single region with multiple ALBs and Aurora Serverless"
            ],
            correct: 2,
            explanation: {
                correct: "Active-active across regions provides the highest availability by eliminating single region as a point of failure and serving traffic from both regions.",
                whyWrong: {
                    0: "Single region deployment can't protect against regional failures",
                    1: "Active-passive has downtime during failover, impacting availability",
                    3: "Single region can't achieve 99.99% with potential regional issues"
                },
                examStrategy: "99.99% availability (52 minutes downtime/year) typically requires multi-region active-active. Single region rarely achieves this."
            }
        },
        {
            id: 'res_011',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company's application experiences periodic spikes in DynamoDB read traffic that cause throttling errors. The spikes are unpredictable and last 5-10 minutes.",
            question: "Which solution provides the MOST resilient handling of read spikes?",
            options: [
                "Enable DynamoDB auto-scaling with target utilization",
                "Implement DynamoDB Accelerator (DAX) caching layer",
                "Switch to on-demand billing mode",
                "Add Global Secondary Indexes for read distribution"
            ],
            correct: 2,
            explanation: {
                correct: "On-demand mode instantly accommodates up to double the previous peak traffic without throttling.",
                whyWrong: {
                    0: "Auto-scaling takes time to react and may not scale fast enough for sudden spikes",
                    1: "DAX helps with cache hits but doesn't prevent throttling for uncached items",
                    3: "GSIs don't help with throttling on the main table"
                },
                examStrategy: "DynamoDB on-demand for unpredictable workloads. Auto-scaling for gradual changes. DAX for microsecond latency."
            }
        },
        {
            id: 'res_012',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A video streaming service needs to ensure content remains available even if an entire AWS region fails. Users should experience minimal interruption during regional failures.",
            question: "Which architecture provides seamless regional failover for video streaming?",
            options: [
                "CloudFront with origin groups and origin failover configured",
                "Route 53 with health checks and manual failover",
                "S3 Cross-Region Replication with static website hosting",
                "Global Accelerator with regional endpoints"
            ],
            correct: 0,
            explanation: {
                correct: "CloudFront origin failover automatically switches to secondary origin when primary fails, providing seamless failover for users.",
                whyWrong: {
                    1: "Manual failover causes service interruption",
                    2: "CRR alone doesn't provide automatic traffic failover",
                    3: "Global Accelerator is better for dynamic content than video streaming"
                },
                examStrategy: "CloudFront origin failover for static/streaming content resilience. Route 53 for DNS-based failover. Know the use cases."
            }
        },
        {
            id: 'res_013',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A batch processing system uses SQS to queue jobs. Some jobs fail due to transient errors and should be retried, while others fail due to data issues and should not be reprocessed.",
            question: "How should the architecture handle both types of failures appropriately?",
            options: [
                "Configure SQS with visibility timeout and dead-letter queue after max receives",
                "Use separate SQS queues for different job types",
                "Implement SNS with retry policies",
                "Use Step Functions with error handling"
            ],
            correct: 0,
            explanation: {
                correct: "Visibility timeout allows retry for transient errors, while DLQ captures messages that fail repeatedly (likely data issues).",
                whyWrong: {
                    1: "Separate queues don't distinguish between error types",
                    2: "SNS doesn't provide message queuing for batch processing",
                    3: "Step Functions adds complexity for simple queue processing"
                },
                examStrategy: "SQS DLQ for poison message handling. Visibility timeout for retries. Redrive policy for recovering DLQ messages."
            }
        },
        {
            id: 'res_014',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to protect their web application from DDoS attacks without managing any infrastructure.",
            question: "Which AWS service provides automatic DDoS protection?",
            options: [
                "AWS Shield Standard",
                "AWS WAF",
                "AWS Network Firewall",
                "Amazon GuardDuty"
            ],
            correct: 0,
            explanation: {
                correct: "Shield Standard provides automatic protection against common DDoS attacks at no additional cost.",
                whyWrong: {
                    1: "WAF requires rule configuration and management",
                    2: "Network Firewall requires setup and management",
                    3: "GuardDuty detects threats but doesn't prevent DDoS"
                },
                examStrategy: "Shield Standard = automatic DDoS protection (free). Shield Advanced = enhanced DDoS ($3000/month). WAF = application layer protection."
            }
        },
        {
            id: 'res_015',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An e-commerce platform needs to maintain shopping cart data across server failures. Cart data should persist for 24 hours even if servers are replaced.",
            question: "Which storage solution provides the BEST resilience for session data?",
            options: [
                "ElastiCache Redis with Multi-AZ and AOF persistence",
                "DynamoDB with point-in-time recovery",
                "EFS mounted on all EC2 instances",
                "RDS with Multi-AZ deployment"
            ],
            correct: 0,
            explanation: {
                correct: "ElastiCache Redis Multi-AZ provides automatic failover and AOF persistence ensures data survives node failures.",
                whyWrong: {
                    1: "DynamoDB PITR is for disaster recovery, overkill for session data",
                    2: "EFS has higher latency than needed for session data",
                    3: "RDS is not optimized for key-value session storage"
                },
                examStrategy: "ElastiCache for session data and caching. DynamoDB for permanent NoSQL. RDS for relational data."
            }
        },
        {
            id: 'res_016',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A financial platform requires exactly-once processing of transactions even during system failures. Transactions arrive via API Gateway and must be processed by multiple downstream services.",
            question: "Which architecture ensures exactly-once processing across distributed services?",
            options: [
                "Step Functions with idempotency tokens and DynamoDB for state tracking",
                "SQS FIFO with Lambda and deduplication ID",
                "Kinesis with checkpointing and transaction IDs",
                "EventBridge with replay and deduplication"
            ],
            correct: 0,
            explanation: {
                correct: "Step Functions provides built-in exactly-once execution with idempotency, and DynamoDB tracks processed transaction IDs across services.",
                whyWrong: {
                    1: "SQS FIFO provides exactly-once delivery, not processing across multiple services",
                    2: "Kinesis requires complex application logic for exactly-once",
                    3: "EventBridge doesn't guarantee exactly-once processing"
                },
                examStrategy: "Step Functions for complex workflows with guaranteed execution. SQS FIFO for ordered, deduplicated delivery. Design for idempotency."
            }
        },
        {
            id: 'res_017',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A media company needs to ensure their content metadata remains synchronized across three regions for global access. Updates must propagate within seconds.",
            question: "Which database solution provides multi-region synchronization with fast propagation?",
            options: [
                "DynamoDB Global Tables with multi-region replication",
                "Aurora Global Database with write forwarding",
                "RDS with read replicas in each region",
                "ElastiCache Global Datastore"
            ],
            correct: 0,
            explanation: {
                correct: "DynamoDB Global Tables provide active-active replication across regions with typically sub-second propagation.",
                whyWrong: {
                    1: "Aurora Global Database has one primary region for writes",
                    2: "RDS read replicas are read-only and have replication lag",
                    3: "ElastiCache Global Datastore is primarily for caching, not persistent storage"
                },
                examStrategy: "DynamoDB Global Tables for multi-region active-active. Aurora Global for read-local, write-primary patterns."
            }
        },
        {
            id: 'res_018',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company needs to ensure their Lambda functions continue processing events even if some invocations fail.",
            question: "Which feature provides automatic retry capability for failed Lambda invocations?",
            options: [
                "Lambda destinations with retry configuration",
                "Lambda reserved concurrency",
                "Lambda provisioned concurrency",
                "Lambda layers"
            ],
            correct: 0,
            explanation: {
                correct: "Lambda destinations handle both successful and failed invocations with configurable retry attempts.",
                whyWrong: {
                    1: "Reserved concurrency limits concurrent executions, doesn't handle retries",
                    2: "Provisioned concurrency reduces cold starts, not for retry logic",
                    3: "Layers share code/libraries, don't provide retry functionality"
                },
                examStrategy: "Lambda destinations for async invocation handling. DLQ for failed events. Built-in retry for stream-based triggers."
            }
        },
        {
            id: 'res_019',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A IoT platform collects sensor data from thousands of devices. Some devices occasionally send duplicate messages due to network issues.",
            question: "How should the architecture handle duplicate message detection at scale?",
            options: [
                "Kinesis Data Streams with partition keys and application-level deduplication",
                "IoT Core with MQTT QoS 2 (exactly once delivery)",
                "SQS FIFO with content-based deduplication",
                "Direct writes to DynamoDB with conditional expressions"
            ],
            correct: 2,
            explanation: {
                correct: "SQS FIFO with content-based deduplication automatically removes duplicates based on message content hash.",
                whyWrong: {
                    0: "Kinesis doesn't provide built-in deduplication",
                    1: "MQTT QoS 2 has high overhead and latency",
                    3: "Direct writes could overwhelm DynamoDB with thousands of devices"
                },
                examStrategy: "SQS FIFO for automatic deduplication. Know the 5-minute deduplication window. Content-based vs message ID deduplication."
            }
        },
        {
            id: 'res_020',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A global social media platform needs to handle 10 million concurrent WebSocket connections for real-time messaging with automatic failover.",
            question: "Which architecture supports massive WebSocket scaling with resilience?",
            options: [
                "API Gateway WebSockets with Lambda and DynamoDB for connection tracking",
                "ALB with sticky sessions and Auto Scaling groups",
                "AWS AppSync with GraphQL subscriptions",
                "ELB Classic with TCP load balancing"
            ],
            correct: 0,
            explanation: {
                correct: "API Gateway WebSockets scales to millions of connections with serverless backend and DynamoDB for distributed state management.",
                whyWrong: {
                    1: "ALB doesn't support WebSocket connection migration during scaling",
                    2: "AppSync subscriptions are better for smaller scale real-time updates",
                    3: "Classic ELB has limited WebSocket support"
                },
                examStrategy: "API Gateway for managed WebSockets at scale. ALB supports WebSockets but consider connection state. AppSync for GraphQL real-time."
            }
        },
        {
            id: 'res_021',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A backup system needs to store 500TB of data with 11 nines (99.999999999%) durability and the ability to restore within 12 hours.",
            question: "Which storage solution meets the durability and restore requirements?",
            options: [
                "S3 Standard with cross-region replication",
                "S3 Glacier Flexible Retrieval",
                "EBS snapshots with multi-region copies",
                "AWS Backup with vault lock"
            ],
            correct: 1,
            explanation: {
                correct: "S3 Glacier Flexible Retrieval provides 11 nines durability with bulk retrieval option (5-12 hours) at low cost.",
                whyWrong: {
                    0: "S3 Standard is more expensive for backup storage",
                    2: "EBS snapshots don't provide 11 nines durability",
                    3: "AWS Backup uses underlying services that may not meet 11 nines"
                },
                examStrategy: "S3 provides 11 nines durability across all storage classes. Match retrieval time to storage class: Instant < Flexible < Deep Archive."
            }
        },
        {
            id: 'res_022',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A web application needs to distribute traffic evenly across EC2 instances in multiple Availability Zones.",
            question: "Which load balancer automatically distributes traffic across AZs?",
            options: [
                "Application Load Balancer with cross-zone load balancing",
                "Network Load Balancer with flow hash algorithm",
                "Classic Load Balancer with session stickiness",
                "Gateway Load Balancer with health checks"
            ],
            correct: 0,
            explanation: {
                correct: "ALB with cross-zone load balancing (enabled by default) evenly distributes requests across all registered targets in all AZs.",
                whyWrong: {
                    1: "NLB flow hash might not distribute evenly across AZs",
                    2: "Session stickiness can cause uneven distribution",
                    3: "Gateway Load Balancer is for virtual appliances, not web traffic"
                },
                examStrategy: "ALB for HTTP/HTTPS. NLB for TCP/UDP/TLS. Gateway LB for third-party appliances. Cross-zone enabled by default on ALB."
            }
        },
        {
            id: 'res_023',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to replicate their on-premises MySQL database to AWS for disaster recovery with minimal data loss.",
            question: "Which solution provides continuous replication with the lowest RPO?",
            options: [
                "AWS Database Migration Service with ongoing replication",
                "AWS DataSync with scheduled transfers",
                "Storage Gateway with volume snapshots",
                "AWS Backup with cross-region copies"
            ],
            correct: 0,
            explanation: {
                correct: "DMS continuous replication provides near-real-time replication with minimal RPO using CDC (Change Data Capture).",
                whyWrong: {
                    1: "DataSync is for file transfer, not database replication",
                    2: "Volume snapshots are point-in-time, not continuous",
                    3: "AWS Backup doesn't support on-premises MySQL"
                },
                examStrategy: "DMS for database migration and replication. DataSync for file systems. Know the difference between batch and continuous."
            }
        },
        {
            id: 'res_024',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A healthcare system requires zero-downtime deployments with the ability to instantly rollback if patient data anomalies are detected.",
            question: "Which deployment strategy provides instant rollback capability?",
            options: [
                "Blue/Green deployment with Route 53 weighted routing",
                "Canary deployment with CloudWatch alarms",
                "Rolling deployment with Auto Scaling",
                "In-place deployment with backup AMIs"
            ],
            correct: 0,
            explanation: {
                correct: "Blue/Green with Route 53 allows instant rollback by shifting traffic weights back to the blue environment.",
                whyWrong: {
                    1: "Canary rollback requires redeployment, not instant",
                    2: "Rolling deployment rollback requires rolling back through instances",
                    3: "In-place rollback requires redeployment from AMIs"
                },
                examStrategy: "Blue/Green for instant rollback. Canary for gradual risk reduction. Rolling for resource efficiency."
            }
        },
        {
            id: 'res_025',
            domain: "Domain 2: Design Resilient Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An application needs to process large files (1-10GB) uploaded by users. Processing takes 20-30 minutes and must complete even if users disconnect.",
            question: "Which architecture ensures reliable processing of large file uploads?",
            options: [
                "S3 multipart upload → S3 event → SQS → EC2 Auto Scaling",
                "API Gateway → Lambda → EFS storage → Batch processing",
                "Direct upload to EC2 → Local processing → S3 storage",
                "CloudFront → S3 → Lambda with extended timeout"
            ],
            correct: 0,
            explanation: {
                correct: "S3 multipart handles large uploads reliably, SQS decouples processing from upload, EC2 handles long-running tasks.",
                whyWrong: {
                    1: "API Gateway has payload limits (10MB) and Lambda has 15-minute timeout",
                    2: "Direct EC2 upload creates single point of failure",
                    3: "Lambda maximum timeout (15 min) insufficient for 20-30 min processing"
                },
                examStrategy: "S3 multipart for large uploads. SQS for decoupling. EC2/ECS/Batch for long-running processes. Lambda timeout is 15 minutes max."
            }
        },
        // Continue with more resilience questions...
    {
        id: 'res_026',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company's application uses Auto Scaling groups across three AZs. They need to ensure even distribution of instances across AZs even when instance types have limited capacity.",
        question: "Which Auto Scaling configuration ensures the BEST availability across AZs?",
        options: [
            "Enable capacity rebalancing with multiple instance types in the launch template",
            "Use a single instance type with On-Demand capacity reservations",
            "Configure weighted capacity with preferred instance types",
            "Set minimum instances per AZ in the Auto Scaling group"
        ],
        correct: 0,
        explanation: {
            correct: "Capacity rebalancing with multiple instance types ensures Auto Scaling can maintain even distribution despite capacity constraints.",
            whyWrong: {
                1: "Single instance type creates single point of failure for capacity",
                2: "Weighted capacity doesn't ensure AZ distribution",
                3: "Minimum per AZ isn't a native Auto Scaling feature"
            },
            examStrategy: "Use multiple instance types for resilience. Capacity rebalancing maintains AZ balance. Avoid single points of failure."
        }
    },
    {
        id: 'res_027',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial trading platform requires sub-second failover for their database with zero data loss. The system processes 50,000 transactions per second.",
        question: "Which database solution provides the fastest failover with zero data loss?",
        options: [
            "Amazon Aurora with synchronous replication to a standby instance",
            "RDS Multi-AZ with automatic failover",
            "DynamoDB with point-in-time recovery",
            "ElastiCache with Redis cluster mode"
        ],
        correct: 0,
        explanation: {
            correct: "Aurora provides near-instantaneous failover (typically under 30 seconds) with synchronous replication ensuring zero data loss.",
            whyWrong: {
                1: "RDS Multi-AZ failover takes 60-120 seconds",
                2: "DynamoDB PITR is for recovery, not instant failover",
                3: "ElastiCache is for caching, not primary database storage"
            },
            examStrategy: "Aurora for fastest RDS failover. Know failover times: Aurora <30s, RDS Multi-AZ 60-120s. Synchronous = zero data loss."
        }
    },
    {
        id: 'res_028',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An e-commerce site needs to handle Black Friday traffic that's 50x normal load. The traffic spike lasts 4 hours.",
        question: "Which architecture provides the MOST resilient scaling for this traffic pattern?",
        options: [
            "CloudFront with dynamic content caching and Lambda@Edge for personalization",
            "Auto Scaling with predictive scaling based on previous years",
            "Pre-provisioned EC2 instances with reserved capacity",
            "Kubernetes with horizontal pod autoscaling"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront absorbs the traffic spike at edge locations, Lambda@Edge scales automatically without pre-provisioning.",
            whyWrong: {
                1: "Predictive scaling might not accurately predict 50x spikes",
                2: "Pre-provisioned instances are expensive for 4-hour spike",
                3: "Kubernetes still requires underlying compute capacity"
            },
            examStrategy: "Edge caching for traffic spikes. Serverless for automatic scaling. Pre-provisioning is expensive for short spikes."
        }
    },
    {
        id: 'res_029',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to ensure their application remains available during AWS service outages in a single AZ.",
        question: "What is the MINIMUM architecture requirement for AZ failure resilience?",
        options: [
            "Deploy resources across multiple AZs with load balancing",
            "Use larger instance types for better reliability",
            "Enable detailed monitoring with CloudWatch",
            "Implement hourly snapshots of all resources"
        ],
        correct: 0,
        explanation: {
            correct: "Multi-AZ deployment is the fundamental requirement for surviving AZ failures.",
            whyWrong: {
                1: "Instance size doesn't protect against AZ failure",
                2: "Monitoring detects but doesn't prevent outages",
                3: "Snapshots help with recovery but not availability"
            },
            examStrategy: "Multi-AZ is fundamental for high availability. Single AZ = single point of failure. Load balancers automatically route around failed AZs."
        }
    },
    {
        id: 'res_030',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A media streaming service needs to ensure video content remains available even if their primary origin server fails. Videos are stored in S3.",
        question: "Which CloudFront configuration provides the BEST origin resilience?",
        options: [
            "Origin group with primary and secondary S3 buckets in different regions",
            "Single S3 origin with Transfer Acceleration",
            "Multiple behaviors pointing to the same origin",
            "Custom origin with EC2 Auto Scaling"
        ],
        correct: 0,
        explanation: {
            correct: "Origin groups provide automatic failover to secondary origins when primary fails, ensuring content availability.",
            whyWrong: {
                1: "Transfer Acceleration is for uploads, not origin resilience",
                2: "Multiple behaviors with same origin don't provide failover",
                3: "EC2 origins add complexity compared to S3 resilience"
            },
            examStrategy: "Origin groups for automatic failover. CloudFront shields origins from direct traffic. S3 for simple, resilient origins."
        }
    },
    {
        id: 'res_031',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A global bank needs their disaster recovery site to be ready within 15 minutes with data loss of maximum 1 minute. The production site runs 100+ applications.",
        question: "Which disaster recovery strategy meets these aggressive RTO/RPO requirements?",
        options: [
            "Multi-site active-active with synchronous replication",
            "Warm standby with asynchronous replication",
            "Pilot light with automated CloudFormation deployment",
            "Backup and restore with point-in-time recovery"
        ],
        correct: 0,
        explanation: {
            correct: "Active-active with synchronous replication is the only option meeting 15-minute RTO and 1-minute RPO at this scale.",
            whyWrong: {
                1: "Async replication can't guarantee 1-minute RPO",
                2: "Pilot light can't activate 100+ applications in 15 minutes",
                3: "Backup and restore takes hours, not minutes"
            },
            examStrategy: "Active-active for aggressive RTO/RPO. Synchronous replication for minimal data loss. Cost increases with lower RTO/RPO."
        }
    },
    {
        id: 'res_032',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A SaaS application experiences database connection pool exhaustion during traffic spikes, causing application failures.",
        question: "Which solution provides the MOST resilient database connection management?",
        options: [
            "RDS Proxy with connection pooling and multiplexing",
            "Increase RDS instance size for more connections",
            "Implement application-level connection pooling",
            "Use read replicas to distribute connections"
        ],
        correct: 0,
        explanation: {
            correct: "RDS Proxy manages connection pooling centrally, multiplexing many client connections over fewer database connections.",
            whyWrong: {
                1: "Larger instances have connection limits and don't solve pooling",
                2: "Application pooling doesn't help with Lambda or serverless",
                3: "Read replicas help with read load, not connection management"
            },
            examStrategy: "RDS Proxy for connection pooling, especially with serverless. Reduces database load and improves resilience."
        }
    },
    {
        id: 'res_033',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A web application needs to continue serving cached content even if the origin server becomes unavailable.",
        question: "Which caching solution provides the BEST resilience for origin failures?",
        options: [
            "CloudFront with custom error pages and long TTLs",
            "ElastiCache in front of the database",
            "Browser caching with local storage",
            "EBS volume caching on EC2"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront continues serving cached content even when origin is down, custom error pages maintain user experience.",
            whyWrong: {
                1: "ElastiCache doesn't help if web servers are down",
                2: "Browser caching doesn't help new visitors",
                3: "EBS caching doesn't survive instance failures"
            },
            examStrategy: "CloudFront serves stale content during origin failures. Long TTLs increase cache resilience. Always implement error pages."
        }
    },
    {
        id: 'res_034',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to replicate their on-premises VMware environment to AWS for disaster recovery with minimal ongoing costs.",
        question: "Which service provides the MOST cost-effective VMware DR solution?",
        options: [
            "AWS Elastic Disaster Recovery with continuous replication",
            "VMware Cloud on AWS with stretched clusters",
            "EC2 with VM Import/Export and regular snapshots",
            "AWS Backup with VMware integration"
        ],
        correct: 0,
        explanation: {
            correct: "Elastic Disaster Recovery continuously replicates servers with minimal compute costs until failover is needed.",
            whyWrong: {
                1: "VMware Cloud on AWS is expensive for just DR",
                2: "VM Import/Export doesn't provide continuous replication",
                3: "AWS Backup doesn't support on-premises VMware"
            },
            examStrategy: "Elastic Disaster Recovery for cost-effective DR. VMware Cloud for full VMware compatibility. Consider ongoing costs."
        }
    },
    {
        id: 'res_035',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A real-time gaming platform needs to maintain session state for millions of concurrent players with instant failover if a server fails.",
        question: "Which architecture provides the BEST session resilience for real-time gaming?",
        options: [
            "ElastiCache for Redis with cluster mode and auto-failover",
            "DynamoDB with global secondary indexes",
            "Sticky sessions with Application Load Balancer",
            "EFS for shared session storage"
        ],
        correct: 0,
        explanation: {
            correct: "Redis cluster mode provides sharding for scale, auto-failover for resilience, and sub-millisecond latency for gaming.",
            whyWrong: {
                1: "DynamoDB has higher latency than Redis for session data",
                2: "Sticky sessions lost on server failure",
                3: "EFS has high latency for session operations"
            },
            examStrategy: "Redis for real-time session state. Cluster mode for scale and resilience. Gaming requires lowest possible latency."
        }
    },
    {
        id: 'res_036',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A batch processing system needs to handle job failures gracefully and automatically retry failed jobs with exponential backoff.",
        question: "Which service provides built-in retry logic with exponential backoff?",
        options: [
            "AWS Step Functions with retry policies",
            "SQS with visibility timeout",
            "Lambda with asynchronous invocation",
            "AWS Batch with job dependencies"
        ],
        correct: 0,
        explanation: {
            correct: "Step Functions provides declarative retry policies with exponential backoff and maximum attempts configuration.",
            whyWrong: {
                1: "SQS requires application-level retry logic",
                2: "Lambda async has simple retry, not exponential backoff",
                3: "Batch handles dependencies but not retry logic"
            },
            examStrategy: "Step Functions for complex workflows with retry logic. Built-in error handling. Exponential backoff prevents thundering herd."
        }
    },
    {
        id: 'res_037',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to ensure their critical data in S3 is protected against accidental deletion.",
        question: "Which S3 feature provides the BEST protection against accidental deletion?",
        options: [
            "Enable versioning and MFA Delete",
            "Cross-region replication",
            "Lifecycle policies",
            "S3 Intelligent-Tiering"
        ],
        correct: 0,
        explanation: {
            correct: "Versioning preserves deleted objects as previous versions, MFA Delete requires additional authentication for permanent deletion.",
            whyWrong: {
                1: "CRR helps with regional failure, not accidental deletion",
                2: "Lifecycle policies automatically delete objects",
                3: "Intelligent-Tiering is for cost optimization, not deletion protection"
            },
            examStrategy: "Versioning for deletion protection. MFA Delete for additional security. Object Lock for compliance requirements."
        }
    },
    {
        id: 'res_038',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A microservices application needs to handle cascading failures where one service failure doesn't bring down the entire system.",
        question: "Which pattern provides the BEST protection against cascading failures?",
        options: [
            "Circuit breaker pattern with fallback responses",
            "Synchronous API calls with retries",
            "Shared database for all microservices",
            "Service mesh with unlimited retries"
        ],
        correct: 0,
        explanation: {
            correct: "Circuit breaker pattern stops calling failing services and provides fallback responses, preventing cascade failures.",
            whyWrong: {
                1: "Synchronous calls with retries can amplify failures",
                2: "Shared database creates coupling and single point of failure",
                3: "Unlimited retries can overwhelm recovering services"
            },
            examStrategy: "Circuit breaker for fault isolation. Asynchronous communication for resilience. Avoid tight coupling between services."
        }
    },
    {
        id: 'res_039',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A blockchain application needs to maintain consistency across distributed nodes while handling network partitions and node failures.",
        question: "Which database provides the BEST consistency and partition tolerance for distributed systems?",
        options: [
            "Amazon QLDB with immutable ledger",
            "DynamoDB with strong consistency and transactions",
            "Aurora with multi-master configuration",
            "DocumentDB with majority write concern"
        ],
        correct: 1,
        explanation: {
            correct: "DynamoDB provides strong consistency, ACID transactions, and automatic partition handling for distributed systems.",
            whyWrong: {
                0: "QLDB is centralized, not distributed like blockchain",
                2: "Aurora multi-master has regional limitations",
                3: "DocumentDB write concerns don't guarantee consistency during partitions"
            },
            examStrategy: "DynamoDB for distributed consistency. QLDB for centralized ledger. Consider CAP theorem tradeoffs."
        }
    },
    {
        id: 'res_040',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their containerized applications automatically recover from container failures without manual intervention.",
        question: "Which container orchestration feature provides automatic container recovery?",
        options: [
            "ECS service with desired count and health checks",
            "EC2 with docker restart policies",
            "Lambda functions instead of containers",
            "Batch jobs with retry configuration"
        ],
        correct: 0,
        explanation: {
            correct: "ECS services automatically maintain desired count of healthy containers, replacing failed ones automatically.",
            whyWrong: {
                1: "Docker restart policies don't handle host failures",
                2: "Lambda isn't a container orchestration solution",
                3: "Batch is for job processing, not service orchestration"
            },
            examStrategy: "ECS/EKS services for container resilience. Health checks for failure detection. Automatic replacement maintains availability."
        }
    },
    {
        id: 'res_041',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A static website needs to remain available even during S3 service disruptions in the primary region.",
        question: "What is the SIMPLEST way to ensure static website availability during regional S3 issues?",
        options: [
            "CloudFront distribution with S3 origin",
            "S3 Cross-Region Replication to multiple regions",
            "EC2 instances serving static files",
            "EFS with multi-AZ deployment"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront caches static content globally, serving it even when S3 origin is unavailable.",
            whyWrong: {
                1: "CRR requires additional configuration and failover logic",
                2: "EC2 is complex and expensive for static content",
                3: "EFS is for shared file systems, not web hosting"
            },
            examStrategy: "CloudFront for static content resilience. Caching provides availability during origin failures. Simplest solution often best."
        }
    },
    {
        id: 'res_042',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A data pipeline processes events from multiple sources. Some events arrive out of order or duplicated due to network issues.",
        question: "Which stream processing solution handles out-of-order and duplicate events BEST?",
        options: [
            "Kinesis Data Analytics with windowing and deduplication",
            "SQS Standard queue with application logic",
            "SNS with message filtering",
            "Direct Lambda invocations with DynamoDB"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis Data Analytics provides built-in windowing for out-of-order events and deduplication capabilities.",
            whyWrong: {
                1: "SQS Standard doesn't guarantee order or deduplication",
                2: "SNS doesn't handle ordering or deduplication",
                3: "Direct Lambda invocations lack stream processing features"
            },
            examStrategy: "Kinesis Analytics for complex stream processing. Windowing for out-of-order events. Built-in vs custom deduplication."
        }
    },
    {
        id: 'res_043',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A social media platform needs to handle viral content that can spike from 100 to 10 million requests per minute within seconds.",
        question: "Which architecture provides instant scaling for viral content?",
        options: [
            "CloudFront with DynamoDB and on-demand scaling",
            "Auto Scaling with target tracking at 50% CPU",
            "Lambda with reserved concurrency",
            "ECS with application auto-scaling"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront absorbs spikes instantly at edge, DynamoDB on-demand handles up to double previous peak instantly.",
            whyWrong: {
                1: "Auto Scaling takes minutes to respond to spikes",
                2: "Reserved concurrency sets limits, not good for spikes",
                3: "ECS auto-scaling not fast enough for viral spikes"
            },
            examStrategy: "Edge caching for viral content. DynamoDB on-demand for unpredictable spikes. Traditional scaling too slow for viral."
        }
    },
    {
        id: 'res_044',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their data remains available even if an entire AWS region becomes unavailable, with maximum 1 hour of data loss.",
        question: "Which backup strategy provides regional failure protection with 1-hour RPO?",
        options: [
            "AWS Backup with cross-region copy and hourly schedules",
            "S3 Cross-Region Replication with RTC",
            "Database snapshots copied manually to another region",
            "Multi-region active-active deployment"
        ],
        correct: 0,
        explanation: {
            correct: "AWS Backup automates hourly backups and cross-region copies, meeting the 1-hour RPO requirement.",
            whyWrong: {
                1: "S3 CRR is near real-time but doesn't cover all data types",
                2: "Manual copies are error-prone and might miss RPO",
                3: "Active-active is complex and expensive for 1-hour RPO"
            },
            examStrategy: "AWS Backup for centralized backup management. Automated cross-region copies for regional resilience. Match solution to RPO."
        }
    },
    {
        id: 'res_045',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to prevent their Auto Scaling group from terminating instances that are processing important batch jobs.",
        question: "How can specific instances be protected from Auto Scaling termination?",
        options: [
            "Enable instance scale-in protection",
            "Use termination policies favoring newest instances",
            "Set minimum capacity equal to desired capacity",
            "Disable Auto Scaling during batch processing"
        ],
        correct: 0,
        explanation: {
            correct: "Instance scale-in protection prevents Auto Scaling from terminating protected instances during scale-in events.",
            whyWrong: {
                1: "Termination policies don't guarantee specific instance protection",
                2: "Equal min/desired prevents all scaling in",
                3: "Disabling Auto Scaling removes resilience benefits"
            },
            examStrategy: "Scale-in protection for batch processing. Temporary protection during critical operations. API/CLI to set protection."
        }
    },
    {
        id: 'res_046',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A financial application requires all database transactions to be recoverable to any point in time within the last 35 days.",
        question: "Which database solution provides point-in-time recovery for 35 days?",
        options: [
            "Aurora with backtrack enabled for 35-day window",
            "RDS with automated backups set to 35-day retention",
            "DynamoDB with continuous backups",
            "DocumentDB with daily snapshots"
        ],
        correct: 1,
        explanation: {
            correct: "RDS automated backups support up to 35 days retention with point-in-time recovery to any second.",
            whyWrong: {
                0: "Aurora backtrack maximum is 72 hours, not 35 days",
                2: "DynamoDB PITR limited to 35 days but question asks for database transactions",
                3: "Daily snapshots don't provide point-in-time granularity"
            },
            examStrategy: "RDS automated backups for PITR up to 35 days. Aurora backtrack for fast rewind within 72 hours. Know the limits."
        }
    },
    {
        id: 'res_047',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A video processing pipeline must handle failures at any stage without losing video files or requiring complete reprocessing.",
        question: "Which architecture provides the MOST resilient video processing pipeline?",
        options: [
            "Step Functions with task tokens, S3 for state storage, and SQS for each stage",
            "Lambda functions chained with SNS topics",
            "ECS tasks with shared EFS storage",
            "Kinesis Video Streams with Lambda processors"
        ],
        correct: 0,
        explanation: {
            correct: "Step Functions orchestrates the workflow with checkpoints, S3 provides durable storage, SQS enables retry at each stage.",
            whyWrong: {
                1: "Lambda chaining doesn't handle mid-pipeline failures well",
                2: "EFS sharing creates dependencies and potential corruption",
                3: "Kinesis Video Streams is for ingestion, not processing orchestration"
            },
            examStrategy: "Step Functions for complex workflows. Checkpointing for resumable processing. Decouple stages for resilience."
        }
    },
    {
        id: 'res_048',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to ensure their application can handle the failure of an entire AWS region with minimal manual intervention.",
        question: "Which service enables automated regional failover for applications?",
        options: [
            "Route 53 with health checks and failover routing",
            "CloudFront with multiple origins",
            "Global Accelerator with endpoint weights",
            "Transit Gateway with VPN backup"
        ],
        correct: 0,
        explanation: {
            correct: "Route 53 health checks detect regional failures and automatically failover DNS to healthy regions.",
            whyWrong: {
                1: "CloudFront is for content delivery, not application failover",
                2: "Global Accelerator requires manual weight adjustments",
                3: "Transit Gateway is for network connectivity, not application failover"
            },
            examStrategy: "Route 53 for DNS-based failover. Health checks for automatic detection. Multi-region deployment prerequisite."
        }
    },
    {
        id: 'res_049',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to protect their web application from common DDoS attacks without managing infrastructure.",
        question: "Which AWS service provides automatic DDoS protection at no additional cost?",
        options: [
            "AWS Shield Standard",
            "AWS WAF",
            "AWS Network Firewall",
            "Security Groups"
        ],
        correct: 0,
        explanation: {
            correct: "Shield Standard provides automatic protection against common DDoS attacks for all AWS customers at no additional charge.",
            whyWrong: {
                1: "WAF requires configuration and has costs",
                2: "Network Firewall requires setup and management",
                3: "Security Groups don't protect against DDoS"
            },
            examStrategy: "Shield Standard = free, automatic DDoS protection. Shield Advanced = enhanced protection with support. Always enabled."
        }
    },
    {
        id: 'res_050',
        domain: "Domain 2: Design Resilient Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An IoT application collects data from 100,000 sensors. The application must not lose data even if processing systems fail.",
        question: "Which data ingestion solution provides the HIGHEST durability for IoT data?",
        options: [
            "AWS IoT Core with rules engine writing to S3",
            "Direct HTTP POST to API Gateway and Lambda",
            "Kinesis Data Firehose with error record handling",
            "SQS with long message retention"
        ],
        correct: 0,
        explanation: {
            correct: "IoT Core provides durable message routing, rules engine ensures reliable delivery to S3 for permanent storage.",
            whyWrong: {
                1: "API Gateway has throttling limits for 100,000 sensors",
                2: "Firehose has retry limits and potential data loss",
                3: "SQS has message size and retention limitations"
            },
            examStrategy: "IoT Core for IoT device management. Rules engine for reliable routing. S3 for durable storage. Purpose-built services."
        }
    }

],
        
    // Domain 3: Design High-Performing Architectures (120 questions - 24%)
    performance: [
        {
            id: 'perf_001',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A news website experiences 10x traffic spikes during breaking news events. The site serves both static content and dynamic API responses.",
            question: "Which caching strategy provides the BEST performance during traffic spikes?",
            options: [
                "CloudFront for static content, ElastiCache for database queries",
                "ElastiCache for all content with lazy loading",
                "S3 with Transfer Acceleration for all content",
                "API Gateway caching for all requests"
            ],
            correct: 0,
            explanation: {
                correct: "CloudFront handles static content at edge locations while ElastiCache reduces database load for dynamic content, providing comprehensive caching.",
                whyWrong: {
                    1: "ElastiCache alone doesn't help with static content delivery",
                    2: "Transfer Acceleration is for uploads, not content delivery",
                    3: "API Gateway caching doesn't help with static content"
                },
                examStrategy: "Layer your caching: CloudFront for static, ElastiCache for database, API Gateway for API responses."
            }
        },
        {
            id: 'perf_002',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A real-time analytics platform needs to process 1 million transactions per second and provide query results within 100ms. Data must be available for queries immediately after ingestion.",
            question: "Which architecture provides the required ingestion rate and query performance?",
            options: [
                "Kinesis Data Streams → Kinesis Analytics → ElastiCache for serving",
                "API Gateway → Lambda → DynamoDB with DAX",
                "Kinesis Firehose → S3 → Athena with partitioning",
                "SQS → Lambda → RDS with read replicas"
            ],
            correct: 0,
            explanation: {
                correct: "Kinesis Data Streams handles million TPS ingestion, Analytics provides real-time processing, ElastiCache serves sub-100ms queries.",
                whyWrong: {
                    1: "Lambda has concurrency limits that would throttle at this scale",
                    2: "Firehose to S3 has minutes of delay, not real-time",
                    3: "SQS and RDS can't handle this transaction volume"
                },
                examStrategy: "For real-time analytics at scale: Kinesis Data Streams ingestion → Kinesis Analytics processing → ElastiCache/DynamoDB serving."
            }
        },
        {
            id: 'perf_003',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A video streaming platform needs to deliver 4K content globally with minimal buffering. Users are distributed across all continents.",
            question: "Which content delivery solution provides the BEST global performance?",
            options: [
                "CloudFront with S3 origins and Regional Edge Caches enabled",
                "S3 with Transfer Acceleration and byte-range fetches",
                "EC2 instances in multiple regions with Route 53 geolocation",
                "AWS Global Accelerator with ALB endpoints"
            ],
            correct: 0,
            explanation: {
                correct: "CloudFront with Regional Edge Caches provides optimal caching hierarchy for large video files with global distribution.",
                whyWrong: {
                    1: "Transfer Acceleration is for uploads, not optimized for streaming delivery",
                    2: "Managing EC2 instances globally is complex and expensive",
                    3: "Global Accelerator is for dynamic content, not optimal for video files"
                },
                examStrategy: "CloudFront is the answer for global content delivery. Regional Edge Caches improve performance for large files."
            }
        },
        {
            id: 'perf_004',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A web application's database queries are taking several seconds, causing poor user experience. Read queries significantly outnumber writes.",
            question: "What is the QUICKEST way to improve read performance?",
            options: [
                "Add RDS read replicas and distribute read traffic",
                "Migrate to DynamoDB for better performance",
                "Increase RDS instance size to maximum available",
                "Implement database sharding"
            ],
            correct: 0,
            explanation: {
                correct: "Read replicas provide immediate read scaling by distributing read queries across multiple database instances.",
                whyWrong: {
                    1: "Migration is complex and time-consuming, not the quickest solution",
                    2: "Scaling up has limits and doesn't scale read capacity horizontally",
                    3: "Sharding is complex to implement and maintain"
                },
                examStrategy: "Read replicas for read scaling, Multi-AZ for availability. Scaling up for write performance, scaling out for read performance."
            }
        },
        {
            id: 'perf_005',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An e-commerce application needs to handle flash sales where traffic increases by 1000% within seconds. The application uses Lambda functions and DynamoDB.",
            question: "Which configuration ensures Lambda functions can handle the sudden traffic spike?",
            options: [
                "Configure Lambda provisioned concurrency based on expected peak",
                "Set Lambda reserved concurrency to maximum limit",
                "Enable Lambda auto-scaling with target tracking",
                "Use Lambda@Edge for geographic distribution"
            ],
            correct: 0,
            explanation: {
                correct: "Provisioned concurrency keeps Lambda functions warm and ready, eliminating cold starts during traffic spikes.",
                whyWrong: {
                    1: "Reserved concurrency sets a limit but doesn't pre-warm functions",
                    2: "Lambda auto-scales by default, target tracking doesn't apply",
                    3: "Lambda@Edge is for CloudFront, not for handling backend spikes"
                },
                examStrategy: "Provisioned concurrency for predictable spikes, reserved concurrency for throttling. Know the difference."
            }
        },
        {
            id: 'perf_006',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A gaming platform needs to maintain player session state with sub-millisecond access times across multiple game servers in different AZs.",
            question: "Which storage solution provides sub-millisecond latency for session data?",
            options: [
                "ElastiCache for Redis with cluster mode enabled",
                "DynamoDB with strongly consistent reads",
                "EFS with performance mode optimized",
                "RDS with Multi-AZ and read replicas"
            ],
            correct: 0,
            explanation: {
                correct: "ElastiCache Redis provides in-memory storage with microsecond latency and cluster mode for high availability across AZs.",
                whyWrong: {
                    1: "DynamoDB provides single-digit millisecond latency, not sub-millisecond",
                    2: "EFS is file storage with higher latency than required",
                    3: "RDS has much higher latency being disk-based storage"
                },
                examStrategy: "ElastiCache for microsecond latency (in-memory), DynamoDB for millisecond latency (SSD), RDS for traditional database needs."
            }
        },
        {
            id: 'perf_007',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A data processing pipeline needs to transform 100TB of data daily. The processing is CPU-intensive and can be parallelized.",
            question: "Which compute solution provides the BEST price-performance for this workload?",
            options: [
                "EC2 Spot Instances with instance fleets across multiple instance types",
                "Lambda functions with maximum memory allocation",
                "Fargate tasks with maximum CPU allocation",
                "EC2 On-Demand instances with dedicated hosts"
            ],
            correct: 0,
            explanation: {
                correct: "Spot Instances provide up to 90% discount for batch processing, and instance fleets ensure capacity availability.",
                whyWrong: {
                    1: "Lambda has 15-minute timeout, not suitable for large batch processing",
                    2: "Fargate is more expensive than Spot for large-scale batch processing",
                    3: "On-Demand with dedicated hosts is the most expensive option"
                },
                examStrategy: "Spot Instances for batch/fault-tolerant workloads. On-Demand for critical. Reserved for steady-state. Savings Plans for flexibility."
            }
        },
        {
            id: 'perf_008',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A mobile app backend needs to reduce API response times. The API responses change based on user but remain same for each user for hours.",
            question: "Where should caching be implemented for best performance?",
            options: [
                "API Gateway with caching key based on user ID",
                "CloudFront with custom headers for user identification",
                "Lambda function memory for in-function caching",
                "S3 with pre-generated responses per user"
            ],
            correct: 0,
            explanation: {
                correct: "API Gateway caching with user ID as cache key provides dedicated cache per user at the API layer.",
                whyWrong: {
                    1: "CloudFront caching with user-specific content reduces cache hit ratio",
                    2: "Lambda memory is not shared between invocations reliably",
                    3: "S3 adds latency and complexity for dynamic API responses"
                },
                examStrategy: "API Gateway caching for API responses, CloudFront for static content. Use cache keys for user-specific caching."
            }
        },
        {
            id: 'perf_009',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A machine learning inference application needs to process images with consistent low latency. GPU acceleration is required.",
            question: "Which deployment option provides the MOST consistent inference performance?",
            options: [
                "EC2 G4 instances with Elastic Inference accelerators",
                "SageMaker endpoints with automatic scaling",
                "Lambda functions with container image support",
                "ECS on EC2 with GPU-enabled instances"
            ],
            correct: 1,
            explanation: {
                correct: "SageMaker endpoints provide managed inference with automatic scaling and consistent performance for ML workloads.",
                whyWrong: {
                    0: "Elastic Inference is being deprecated in favor of SageMaker",
                    2: "Lambda doesn't support GPU acceleration",
                    3: "ECS requires more management compared to SageMaker endpoints"
                },
                examStrategy: "SageMaker for ML inference, EC2 with GPU for training or custom requirements. Lambda for simple, CPU-based inference."
            }
        },
        {
            id: 'perf_010',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A financial application requires database queries to complete within 5ms for regulatory compliance. The database has 50TB of data with complex queries.",
            question: "Which database solution can meet the 5ms query requirement?",
            options: [
                "Amazon DynamoDB with partition key design and projection indexes",
                "Amazon Aurora with parallel query enabled",
                "Amazon Redshift with result caching",
                "Amazon RDS with Provisioned IOPS"
            ],
            correct: 0,
            explanation: {
                correct: "DynamoDB provides consistent single-digit millisecond performance with proper key design and projections for query patterns.",
                whyWrong: {
                    1: "Aurora parallel query improves performance but can't guarantee 5ms for complex queries",
                    2: "Redshift is for analytics, not optimized for single-query latency",
                    3: "RDS even with high IOPS can't guarantee 5ms for complex queries on 50TB"
                },
                examStrategy: "DynamoDB for guaranteed single-digit millisecond latency. Aurora for relational with good performance. Design matters most."
            }
        },
        {
            id: 'perf_011',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A photo-sharing application allows users to upload images that are processed into multiple resolutions. Users complain about slow thumbnail generation.",
            question: "Which solution provides the FASTEST thumbnail generation for uploaded images?",
            options: [
                "Lambda with Lambda extensions for image processing libraries",
                "EC2 with GPU instances and SQS queue",
                "ECS with Fargate and parallel processing",
                "Lambda@Edge with CloudFront"
            ],
            correct: 3,
            explanation: {
                correct: "Lambda@Edge can generate thumbnails at CloudFront edge locations, providing lowest latency by processing closer to users.",
                whyWrong: {
                    0: "Regular Lambda has cold start delays and regional latency",
                    1: "GPU is overkill for thumbnail generation and adds cost",
                    2: "Fargate has container startup time that impacts performance"
                },
                examStrategy: "Lambda@Edge for edge computing and image manipulation. Regular Lambda for backend processing. GPU for ML/AI workloads."
            }
        },
        {
            id: 'perf_012',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A real-time bidding platform needs to process 500,000 bid requests per second with response times under 100ms. Each request requires checking user profiles and bid history.",
            question: "Which architecture meets the latency requirements at this scale?",
            options: [
                "API Gateway HTTP APIs → Lambda with provisioned concurrency → DynamoDB with DAX",
                "ALB → ECS on EC2 with placement groups → ElastiCache Redis cluster",
                "API Gateway REST → Step Functions Express → Aurora Serverless",
                "CloudFront → Lambda@Edge → DynamoDB Global Tables"
            ],
            correct: 1,
            explanation: {
                correct: "ALB with ECS on EC2 in placement groups provides predictable low latency, ElastiCache offers sub-millisecond data access for the required scale.",
                whyWrong: {
                    0: "API Gateway adds latency, Lambda has concurrency limits at this scale",
                    2: "Step Functions add orchestration overhead incompatible with 100ms requirement",
                    3: "Lambda@Edge has lower memory/CPU limits not suitable for complex processing"
                },
                examStrategy: "For ultra-low latency at scale: EC2 placement groups, ElastiCache, avoid service chaining. Know service latency characteristics."
            }
        },
        {
            id: 'perf_013',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A data analytics platform needs to query 10TB of CSV files daily. Queries must complete within minutes and support complex SQL operations.",
            question: "Which solution provides the BEST query performance for this workload?",
            options: [
                "S3 with Athena and partitioned Parquet files",
                "Redshift with distribution keys and sort keys",
                "EMR with Spark and HDFS storage",
                "RDS PostgreSQL with read replicas"
            ],
            correct: 0,
            explanation: {
                correct: "Athena with Parquet format and partitioning provides fast, serverless querying with significant compression and columnar optimization.",
                whyWrong: {
                    1: "Redshift requires cluster management and data loading time",
                    2: "EMR requires cluster management and is more complex",
                    3: "RDS cannot efficiently handle 10TB analytical queries"
                },
                examStrategy: "Athena + Parquet for serverless analytics. Redshift for complex analytics with joins. Convert CSV to Parquet for 10x+ performance."
            }
        },
        {
            id: 'perf_014',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A website serves product images to millions of users globally. Images are rarely updated but frequently accessed.",
            question: "What is the MOST effective way to improve image loading performance?",
            options: [
                "Enable S3 Transfer Acceleration",
                "Use CloudFront CDN with S3 origin",
                "Implement ElastiCache in front of S3",
                "Use EC2 instances as image servers"
            ],
            correct: 1,
            explanation: {
                correct: "CloudFront caches images at edge locations globally, providing lowest latency for frequently accessed static content.",
                whyWrong: {
                    0: "Transfer Acceleration is for uploads, not downloads",
                    2: "ElastiCache doesn't cache binary files like images",
                    3: "EC2 instances don't provide global distribution"
                },
                examStrategy: "CloudFront for static content delivery. Transfer Acceleration for uploads. ElastiCache for application data caching."
            }
        },
        {
            id: 'perf_015',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An application requires consistent IOPS performance of 64,000 IOPS for its database. The database size is 10TB.",
            question: "Which EBS volume type and configuration meets these requirements?",
            options: [
                "Single io2 Block Express volume with 64,000 provisioned IOPS",
                "Four io1 volumes with 16,000 IOPS each in RAID 0",
                "gp3 volume with maximum IOPS configuration",
                "Multiple gp2 volumes to achieve required IOPS"
            ],
            correct: 0,
            explanation: {
                correct: "io2 Block Express supports up to 256,000 IOPS per volume and sub-millisecond latency, meeting requirements with a single volume.",
                whyWrong: {
                    1: "RAID 0 adds complexity and potential failure points",
                    2: "gp3 maximum is 16,000 IOPS, insufficient for requirements",
                    3: "gp2 IOPS tied to volume size, complex to manage multiple volumes"
                },
                examStrategy: "io2 Block Express for highest performance (256k IOPS). io1/io2 standard (64k IOPS). gp3 for balanced price/performance (16k IOPS)."
            }
        },
        {
            id: 'perf_016',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A machine learning training job processes 100TB of data with intensive inter-node communication. Training time must be minimized.",
            question: "Which EC2 configuration provides the BEST performance for distributed ML training?",
            options: [
                "P4d instances with Elastic Fabric Adapter (EFA) in a cluster placement group",
                "P3 instances with placement spread strategy across AZs",
                "G4 instances with dedicated hosts",
                "Spot fleet with mixed instance types for cost optimization"
            ],
            correct: 0,
            explanation: {
                correct: "P4d instances provide highest GPU performance, EFA enables high-bandwidth, low-latency networking, cluster placement minimizes network latency.",
                whyWrong: {
                    1: "Spread placement increases network latency between nodes",
                    2: "G4 instances are for inference, not optimal for training",
                    3: "Mixed instances cause performance bottlenecks in distributed training"
                },
                examStrategy: "P4 for training, G4 for inference. EFA for HPC networking. Cluster placement for lowest latency. Don't mix instance types for HPC."
            }
        },
        {
            id: 'perf_017',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A mobile game needs to maintain global leaderboards updated in real-time for 10 million active players.",
            question: "Which solution provides real-time leaderboard updates with global consistency?",
            options: [
                "DynamoDB with Global Secondary Indexes and DynamoDB Streams",
                "ElastiCache Redis with sorted sets",
                "Aurora with read replicas in multiple regions",
                "Neptune graph database with Gremlin queries"
            ],
            correct: 1,
            explanation: {
                correct: "Redis sorted sets are specifically designed for leaderboards with O(log n) operations for score updates and range queries.",
                whyWrong: {
                    0: "DynamoDB GSIs not optimized for constantly changing leaderboard queries",
                    2: "Aurora replication lag impacts real-time consistency",
                    3: "Neptune is for graph relationships, overkill for leaderboards"
                },
                examStrategy: "Redis sorted sets for leaderboards and rankings. DynamoDB for key-value lookups. Know Redis data structures."
            }
        },
        {
            id: 'perf_018',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A web application experiences slow page loads due to multiple API calls required to render each page.",
            question: "Which caching strategy provides the BEST performance improvement?",
            options: [
                "Implement API Gateway caching for GET requests",
                "Add CloudFront caching for API responses",
                "Use browser local storage for caching",
                "Implement server-side rendering with caching"
            ],
            correct: 0,
            explanation: {
                correct: "API Gateway caching reduces backend calls and provides consistent response times for cacheable GET requests.",
                whyWrong: {
                    1: "CloudFront caching for dynamic APIs can cause stale data issues",
                    2: "Browser caching doesn't help first-time visitors",
                    3: "SSR adds server load and complexity"
                },
                examStrategy: "API Gateway caching for API responses. CloudFront for static content. Cache as close to the source as possible."
            }
        },
        {
            id: 'perf_019',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A log processing system ingests 50TB of logs daily and needs to support both real-time alerting and historical analysis.",
            question: "Which architecture provides optimal performance for both use cases?",
            options: [
                "Kinesis Data Streams → Kinesis Analytics for alerts → Firehose → S3 → Athena",
                "CloudWatch Logs → CloudWatch Insights → S3 export",
                "Direct to S3 → Lambda triggers → ElasticSearch",
                "SQS → Lambda → DynamoDB → EMR"
            ],
            correct: 0,
            explanation: {
                correct: "Kinesis Streams enables real-time processing, Analytics provides alerting, Firehose batches to S3 for historical analysis with Athena.",
                whyWrong: {
                    1: "CloudWatch Logs expensive at 50TB/day scale",
                    2: "Direct S3 misses real-time processing capability",
                    3: "SQS not designed for streaming analytics at this scale"
                },
                examStrategy: "Kinesis for streaming data. Split stream for real-time and batch processing. S3 + Athena for historical analysis."
            }
        },
        {
            id: 'perf_020',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A scientific computing workload requires 100 Gbps network throughput between compute nodes for MPI (Message Passing Interface) operations.",
            question: "Which instance and networking configuration achieves 100 Gbps throughput?",
            options: [
                "C5n.18xlarge instances with Elastic Fabric Adapter in cluster placement group",
                "M5.24xlarge instances with enhanced networking",
                "C5.24xlarge instances with SR-IOV",
                "R5n.24xlarge instances with dedicated bandwidth"
            ],
            correct: 0,
            explanation: {
                correct: "C5n.18xlarge provides 100 Gbps network performance, EFA enables low-latency MPI, cluster placement ensures optimal network path.",
                whyWrong: {
                    1: "M5.24xlarge only provides 25 Gbps networking",
                    2: "C5.24xlarge provides 25 Gbps, not 100 Gbps",
                    3: "R5n provides up to 100 Gbps but less compute-optimized than C5n"
                },
                examStrategy: "Instance types with 'n' have enhanced networking. Check specific instance network performance. EFA for HPC/MPI workloads."
            }
        },
        {
            id: 'perf_021',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "An e-commerce site needs to personalize product recommendations for each user based on browsing history. Recommendations must load within 50ms.",
            question: "Which solution provides the fastest personalized recommendations?",
            options: [
                "Amazon Personalize with real-time recommendations API",
                "SageMaker endpoint with custom recommendation model",
                "Lambda function with ElastiCache for user preferences",
                "DynamoDB with pre-computed recommendations"
            ],
            correct: 3,
            explanation: {
                correct: "Pre-computed recommendations in DynamoDB provide consistent single-digit millisecond latency, meeting the 50ms requirement.",
                whyWrong: {
                    0: "Personalize API calls add latency, might exceed 50ms",
                    1: "SageMaker endpoint invocation typically takes 100ms+",
                    2: "Lambda cold starts could exceed 50ms requirement"
                },
                examStrategy: "Pre-compute when possible for lowest latency. Real-time ML adds latency. DynamoDB for predictable performance."
            }
        },
        {
            id: 'perf_022',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company needs to transfer 10TB of data between S3 buckets in different regions as quickly as possible.",
            question: "What is the FASTEST method to copy data between regions?",
            options: [
                "S3 Cross-Region Replication",
                "S3 Batch Operations with parallel transfers",
                "DataSync with multiple threads",
                "AWS CLI with multipart upload"
            ],
            correct: 1,
            explanation: {
                correct: "S3 Batch Operations can use massive parallelization for fastest point-in-time transfer of existing objects.",
                whyWrong: {
                    0: "CRR is for ongoing replication, not one-time transfers",
                    2: "DataSync is for hybrid/on-premises, not S3-to-S3",
                    3: "CLI is slower than Batch Operations for large transfers"
                },
                examStrategy: "S3 Batch Operations for large-scale operations. CRR for ongoing replication. Transfer Family for partner uploads."
            }
        },
        {
            id: 'perf_023',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A video conferencing application needs to minimize latency for users joining from different global locations.",
            question: "Which service provides the LOWEST latency for global users?",
            options: [
                "AWS Global Accelerator with anycast IPs",
                "Route 53 with geolocation routing",
                "CloudFront with custom origins",
                "Direct Connect with virtual interfaces"
            ],
            correct: 0,
            explanation: {
                correct: "Global Accelerator uses anycast IPs to route users to the nearest edge location, then uses AWS backbone for optimal routing.",
                whyWrong: {
                    1: "Geolocation routing doesn't optimize the network path",
                    2: "CloudFront is for content delivery, not optimal for video conferencing",
                    3: "Direct Connect is for specific locations, not global optimization"
                },
                examStrategy: "Global Accelerator for TCP/UDP optimization. CloudFront for HTTP/HTTPS caching. Route 53 for DNS-based routing."
            }
        },
        {
            id: 'perf_024',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A blockchain application needs to store and query 50 billion transaction records with complex relationship queries completing in under 1 second.",
            question: "Which database solution provides the required query performance for relationship data?",
            options: [
                "Amazon Neptune with Gremlin queries and read replicas",
                "DynamoDB with composite keys and GSIs",
                "Amazon QLDB with PartiQL queries",
                "DocumentDB with aggregation pipelines"
            ],
            correct: 0,
            explanation: {
                correct: "Neptune is purpose-built for billions of relationships with millisecond query latency for complex graph traversals.",
                whyWrong: {
                    1: "DynamoDB not optimized for complex relationship queries",
                    2: "QLDB is for ledger/audit, not optimized for relationship queries",
                    3: "DocumentDB better for document stores, not graph relationships"
                },
                examStrategy: "Neptune for graph data. QLDB for immutable ledger. DocumentDB for MongoDB compatibility. Match database to data model."
            }
        },
        {
            id: 'perf_025',
            domain: "Domain 3: Design High-Performing Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A SaaS platform needs to support 100,000 concurrent API requests with sub-second response times. The API performs simple CRUD operations.",
            question: "Which API solution provides the BEST performance at this scale?",
            options: [
                "API Gateway HTTP APIs with Lambda and DynamoDB",
                "API Gateway REST APIs with caching enabled",
                "ALB with ECS Fargate services",
                "AppSync with DynamoDB resolvers"
            ],
            correct: 0,
            explanation: {
                correct: "HTTP APIs have lower latency than REST APIs (60% faster) and DynamoDB provides predictable performance at scale.",
                whyWrong: {
                    1: "REST APIs have higher latency than HTTP APIs",
                    2: "Container cold starts impact response times",
                    3: "AppSync adds GraphQL processing overhead for simple CRUD"
                },
                examStrategy: "HTTP APIs for simple, high-volume APIs. REST APIs for full features. AppSync for GraphQL. Know the performance tradeoffs."
            }
        },
        // Continue with more performance questions...
 {
        id: 'perf_026',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A real-time analytics dashboard needs to display metrics from 10,000 IoT devices with latency under 2 seconds.",
        question: "Which architecture provides the BEST performance for real-time IoT analytics?",
        options: [
            "Kinesis Data Streams → Kinesis Analytics → ElastiCache → WebSocket API",
            "IoT Core → Lambda → DynamoDB → REST API with polling",
            "SQS → EC2 → RDS → GraphQL subscriptions",
            "Direct device connections to WebSocket API Gateway"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis provides real-time streaming, Analytics processes in-flight, ElastiCache serves with sub-second latency, WebSockets push updates.",
            whyWrong: {
                1: "Lambda processing and polling add latency",
                2: "SQS and RDS not optimized for real-time streaming",
                3: "Direct connections don't scale to 10,000 devices"
            },
            examStrategy: "Kinesis for real-time streaming. ElastiCache for low-latency serving. WebSockets for real-time updates."
        }
    },
    {
        id: 'perf_027',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A genomics research platform needs to process 100TB datasets with complex queries completing in under 10 seconds.",
        question: "Which data processing solution meets the 10-second query requirement for 100TB datasets?",
        options: [
            "Amazon Redshift with RA3 nodes and materialized views",
            "Athena with partitioned Parquet files in S3",
            "EMR with Spark and HDFS caching",
            "Aurora with parallel query"
        ],
        correct: 0,
        explanation: {
            correct: "Redshift RA3 nodes separate compute and storage, materialized views pre-compute complex queries for sub-10 second response.",
            whyWrong: {
                1: "Athena on 100TB would take minutes even with optimization",
                2: "EMR requires cluster management and still may not meet 10s requirement",
                3: "Aurora not designed for 100TB analytical queries"
            },
            examStrategy: "Redshift for complex analytics at scale. Materialized views for query acceleration. RA3 for compute/storage separation."
        }
    },
    {
        id: 'perf_028',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A mobile app needs to upload large files (100MB-1GB) from areas with poor network connectivity.",
        question: "Which upload strategy provides the BEST performance for large files over unreliable networks?",
        options: [
            "S3 multipart upload with Transfer Acceleration",
            "Direct PUT to S3 with retry logic",
            "API Gateway with Lambda processing",
            "CloudFront with POST requests"
        ],
        correct: 0,
        explanation: {
            correct: "Multipart upload allows resumable uploads and parallel parts, Transfer Acceleration optimizes routing over poor networks.",
            whyWrong: {
                1: "Single PUT fails completely on network interruption",
                2: "API Gateway has 10MB payload limit",
                3: "CloudFront POST doesn't improve upload performance"
            },
            examStrategy: "Multipart upload for large files and resume capability. Transfer Acceleration for upload optimization. Know service limits."
        }
    },
    {
        id: 'perf_029',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A web application's homepage takes 5 seconds to load due to multiple database queries. The data changes daily.",
        question: "What is the QUICKEST way to improve homepage load time?",
        options: [
            "Implement caching with 24-hour TTL in CloudFront",
            "Add more RDS read replicas",
            "Upgrade to a larger RDS instance",
            "Rewrite queries for better optimization"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront caching eliminates database queries for most users, providing immediate performance improvement.",
            whyWrong: {
                1: "Read replicas don't reduce query time, just distribute load",
                2: "Larger instance has diminishing returns for query optimization",
                3: "Query optimization takes time and may not achieve desired improvement"
            },
            examStrategy: "Caching is often the quickest performance win. Match cache TTL to data change frequency. CloudFront for static/semi-static content."
        }
    },
    {
        id: 'perf_030',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A machine learning platform needs to serve model predictions to 1 million requests per second with P99 latency under 10ms.",
        question: "Which serving architecture meets the latency requirement at this scale?",
        options: [
            "SageMaker multi-model endpoints with Elastic Inference",
            "Lambda functions with provisioned concurrency",
            "ECS on EC2 with application load balancer",
            "EC2 with GPU instances and ElastiCache"
        ],
        correct: 3,
        explanation: {
            correct: "EC2 GPU instances provide dedicated compute for inference, ElastiCache serves cached predictions at sub-millisecond latency.",
            whyWrong: {
                0: "SageMaker endpoints have higher latency overhead",
                1: "Lambda has cold start and concurrency limitations at this scale",
                2: "ALB adds latency, standard ECS lacks GPU optimization"
            },
            examStrategy: "Cache ML predictions when possible. GPU for complex models. Know latency characteristics of services."
        }
    },
    {
        id: 'perf_031',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial trading system requires network latency between components to be under 500 microseconds with 10Gbps throughput.",
        question: "Which EC2 configuration achieves sub-500 microsecond latency?",
        options: [
            "C5n instances in cluster placement group with SR-IOV",
            "M5 instances in spread placement group",
            "T3 instances with enhanced networking",
            "R5 instances across multiple AZs"
        ],
        correct: 0,
        explanation: {
            correct: "Cluster placement provides lowest latency (<500μs), C5n offers enhanced networking, SR-IOV bypasses hypervisor.",
            whyWrong: {
                1: "Spread placement increases latency between instances",
                2: "T3 instances don't support placement groups or required performance",
                3: "Cross-AZ communication adds milliseconds of latency"
            },
            examStrategy: "Cluster placement for ultra-low latency. SR-IOV for kernel bypass. Same-AZ for microsecond latency requirements."
        }
    },
    {
        id: 'perf_032',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A content management system needs to serve personalized content to users globally with minimal latency.",
        question: "Which edge computing solution provides the BEST performance for personalized content?",
        options: [
            "CloudFront with Lambda@Edge for personalization",
            "S3 with Transfer Acceleration",
            "Global Accelerator with regional endpoints",
            "Route 53 with geolocation routing"
        ],
        correct: 0,
        explanation: {
            correct: "Lambda@Edge executes personalization logic at CloudFront edge locations, minimizing round-trip latency.",
            whyWrong: {
                1: "Transfer Acceleration is for uploads, not content serving",
                2: "Global Accelerator doesn't provide compute at edge",
                3: "Route 53 only routes traffic, doesn't serve content"
            },
            examStrategy: "Lambda@Edge for edge compute. CloudFront for global distribution. Personalization at the edge reduces origin load."
        }
    },
    {
        id: 'perf_033',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to improve their database read performance. Their application performs the same complex queries repeatedly.",
        question: "What is the MOST effective way to improve repetitive query performance?",
        options: [
            "Implement query result caching with ElastiCache",
            "Add more CPU to the RDS instance",
            "Create additional indexes on all columns",
            "Switch to NoSQL database"
        ],
        correct: 0,
        explanation: {
            correct: "ElastiCache stores query results in memory, providing microsecond access for repeated queries.",
            whyWrong: {
                1: "More CPU doesn't help if queries are I/O bound",
                2: "Too many indexes slow down writes and increase storage",
                3: "NoSQL migration is complex and may not improve complex queries"
            },
            examStrategy: "Cache frequently accessed data. ElastiCache for query results. In-memory always faster than disk."
        }
    },
    {
        id: 'perf_034',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A SaaS platform needs to generate PDF reports from 10GB datasets in under 30 seconds.",
        question: "Which compute solution provides the performance needed for large report generation?",
        options: [
            "EC2 with memory-optimized instances and local NVMe storage",
            "Lambda with maximum memory allocation",
            "Fargate with 30GB memory configuration",
            "Batch with Spot instances"
        ],
        correct: 0,
        explanation: {
            correct: "Memory-optimized EC2 can handle 10GB in RAM, local NVMe provides fast data access for processing.",
            whyWrong: {
                1: "Lambda has 10GB memory limit, insufficient for dataset",
                2: "Fargate has container startup overhead",
                3: "Batch Spot instances may be interrupted"
            },
            examStrategy: "Memory-optimized for large dataset processing. Local NVMe for temporary high-speed storage. Know service memory limits."
        }
    },
    {
        id: 'perf_035',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A real-time multiplayer game needs to synchronize game state across 1000 players with latency under 50ms globally.",
        question: "Which architecture provides global 50ms latency for game state synchronization?",
        options: [
            "AWS Wavelength zones with 5G edge computing",
            "DynamoDB Global Tables with eventually consistent reads",
            "ElastiCache with cross-region replication",
            "AppSync with GraphQL subscriptions"
        ],
        correct: 0,
        explanation: {
            correct: "Wavelength zones provide ultra-low latency at 5G edge, perfect for real-time gaming requirements.",
            whyWrong: {
                1: "Global Tables have replication lag exceeding 50ms",
                2: "Cross-region replication adds 100ms+ latency",
                3: "AppSync subscriptions not optimized for 1000-player scale"
            },
            examStrategy: "Wavelength for ultra-low latency at edge. 5G networks for mobile gaming. Traditional cloud too far for <50ms globally."
        }
    },
    {
        id: 'perf_036',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An e-commerce platform needs to handle 100,000 concurrent product searches with faceted filtering.",
        question: "Which search solution provides the BEST performance for faceted search at scale?",
        options: [
            "Amazon OpenSearch with dedicated master nodes",
            "DynamoDB with composite keys and GSIs",
            "RDS with full-text search indexes",
            "CloudSearch with multi-AZ deployment"
        ],
        correct: 0,
        explanation: {
            correct: "OpenSearch is optimized for full-text search with faceting, dedicated masters ensure cluster stability at scale.",
            whyWrong: {
                1: "DynamoDB not optimized for full-text search and faceting",
                2: "RDS full-text search doesn't scale well to 100k concurrent",
                3: "CloudSearch has scaling limitations compared to OpenSearch"
            },
            examStrategy: "OpenSearch for complex search requirements. Dedicated masters for production. DynamoDB for key-value lookups."
        }
    },
    {
        id: 'perf_037',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's application is slow because it makes sequential API calls to multiple microservices.",
        question: "How can the application performance be improved?",
        options: [
            "Make API calls in parallel using async/await patterns",
            "Increase timeout values for API calls",
            "Add more servers to handle requests",
            "Implement circuit breakers"
        ],
        correct: 0,
        explanation: {
            correct: "Parallel API calls reduce total wait time from sum of all calls to the slowest single call.",
            whyWrong: {
                1: "Increasing timeouts doesn't improve performance",
                2: "More servers don't help with sequential call patterns",
                3: "Circuit breakers handle failures, not performance"
            },
            examStrategy: "Parallelize independent operations. Async patterns for concurrent execution. Sequential = slow, parallel = fast."
        }
    },
    {
        id: 'perf_038',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A data warehouse needs to run complex analytical queries across 5 years of historical data (50TB) with consistent performance.",
        question: "Which storage strategy provides the BEST query performance for historical analytics?",
        options: [
            "Redshift with data distribution keys and sort keys optimized for query patterns",
            "S3 with Athena and aggressive partitioning",
            "RDS with partitioned tables and read replicas",
            "DynamoDB with time-series tables"
        ],
        correct: 0,
        explanation: {
            correct: "Redshift is purpose-built for analytics, distribution and sort keys optimize query performance on large datasets.",
            whyWrong: {
                1: "Athena slower for complex joins and aggregations at this scale",
                2: "RDS not optimized for 50TB analytical workloads",
                3: "DynamoDB expensive and not suited for complex analytics"
            },
            examStrategy: "Redshift for data warehousing. Distribution keys for parallel processing. Sort keys for query optimization."
        }
    },
    {
        id: 'perf_039',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A video streaming platform needs to transcode uploaded videos into 10 different formats within 5 minutes of upload.",
        question: "Which transcoding architecture meets the 5-minute requirement?",
        options: [
            "Elemental MediaConvert with accelerated transcoding and job priorities",
            "Lambda functions with FFmpeg layers",
            "EC2 GPU instances with parallel processing",
            "Elastic Transcoder with pipeline optimization"
        ],
        correct: 0,
        explanation: {
            correct: "MediaConvert accelerated transcoding processes multiple formats in parallel, priority queues ensure 5-minute SLA.",
            whyWrong: {
                1: "Lambda 15-minute timeout insufficient for video transcoding",
                2: "EC2 requires management and may not parallelize efficiently",
                3: "Elastic Transcoder is legacy, MediaConvert is faster"
            },
            examStrategy: "MediaConvert for video processing. Accelerated transcoding for speed. Purpose-built services over custom solutions."
        }
    },
    {
        id: 'perf_040',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A financial application requires consistent disk performance of 20,000 IOPS with predictable latency.",
        question: "Which storage solution provides guaranteed IOPS with consistent latency?",
        options: [
            "EBS io2 volumes with provisioned IOPS",
            "EBS gp3 volumes with IOPS configuration",
            "Instance store NVMe drives",
            "EFS with provisioned throughput"
        ],
        correct: 0,
        explanation: {
            correct: "io2 provides guaranteed IOPS up to 64,000 with 99.999% durability and consistent sub-millisecond latency.",
            whyWrong: {
                1: "gp3 provides up to 16,000 IOPS, below requirement",
                2: "Instance store is ephemeral, risky for financial data",
                3: "EFS is for file sharing, not high IOPS block storage"
            },
            examStrategy: "io2 for guaranteed IOPS and durability. gp3 for cost-effective performance. Instance store for temporary data only."
        }
    },
    {
        id: 'perf_041',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "Users complain that a website is slow to load from Asia, but fast from North America where the servers are located.",
        question: "What is the MOST effective solution to improve performance for Asian users?",
        options: [
            "Deploy CloudFront distribution with edge locations in Asia",
            "Increase bandwidth on the web servers",
            "Implement database caching",
            "Upgrade to faster web servers"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront edge locations in Asia cache content close to users, eliminating trans-Pacific latency.",
            whyWrong: {
                1: "Bandwidth doesn't reduce latency across oceans",
                2: "Database caching doesn't help with geographic latency",
                3: "Faster servers don't reduce network distance"
            },
            examStrategy: "CDN for geographic performance. Edge locations reduce latency. Distance = latency, caching = solution."
        }
    },
    {
        id: 'perf_042',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A log analysis system needs to search through 1TB of logs per day with complex regex patterns in near real-time.",
        question: "Which solution provides the BEST performance for regex searching at scale?",
        options: [
            "CloudWatch Logs Insights with filter patterns",
            "OpenSearch with Logstash preprocessing",
            "Athena with regex functions on S3 data",
            "Kinesis Analytics with SQL queries"
        ],
        correct: 1,
        explanation: {
            correct: "OpenSearch with Logstash can preprocess and index logs for fast regex searching with near real-time ingestion.",
            whyWrong: {
                0: "CloudWatch Insights has query limitations and slower for complex regex",
                2: "Athena has latency for real-time requirements",
                3: "Kinesis Analytics SQL doesn't support complex regex patterns"
            },
            examStrategy: "OpenSearch for log analytics at scale. Preprocessing improves search performance. Real-time requires indexing."
        }
    },
    {
        id: 'perf_043',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A scientific simulation requires 100 GPU instances to work together with inter-node bandwidth of 400Gbps.",
        question: "Which configuration provides 400Gbps inter-node bandwidth for GPU computing?",
        options: [
            "P4d.24xlarge instances with EFA and cluster placement group",
            "G4dn instances with enhanced networking",
            "P3 instances with dedicated hosts",
            "GPU instances across multiple regions with Direct Connect"
        ],
        correct: 0,
        explanation: {
            correct: "P4d.24xlarge provides 400Gbps networking with EFA for HPC, cluster placement minimizes latency.",
            whyWrong: {
                1: "G4dn maxes at 100Gbps networking",
                2: "P3 provides up to 100Gbps, not 400Gbps",
                3: "Cross-region adds too much latency for HPC"
            },
            examStrategy: "P4d for maximum GPU and network performance. EFA for HPC/ML. Cluster placement for minimum latency."
        }
    },
    {
        id: 'perf_044',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An API needs to handle 50,000 requests per second with response times under 100ms. Response data is user-specific.",
        question: "Which caching strategy provides the BEST performance for user-specific API responses?",
        options: [
            "ElastiCache with user ID as cache key",
            "CloudFront with cache headers based on user",
            "API Gateway caching for all requests",
            "S3 with pre-generated responses per user"
        ],
        correct: 0,
        explanation: {
            correct: "ElastiCache provides sub-millisecond latency with user ID keys, handling 50k RPS with proper sharding.",
            whyWrong: {
                1: "CloudFront user-specific caching reduces cache hit ratio",
                2: "API Gateway caching doesn't work well for user-specific data",
                3: "S3 has higher latency than ElastiCache"
            },
            examStrategy: "ElastiCache for application-level caching. User-specific data needs careful cache key design. In-memory for <100ms."
        }
    },
    {
        id: 'perf_045',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to improve their data transfer speed between their on-premises data center and AWS.",
        question: "Which service provides the FASTEST data transfer speeds to AWS?",
        options: [
            "AWS Direct Connect with dedicated bandwidth",
            "Site-to-Site VPN with multiple tunnels",
            "AWS DataSync over internet",
            "S3 Transfer Acceleration"
        ],
        correct: 0,
        explanation: {
            correct: "Direct Connect provides dedicated network connectivity up to 100Gbps with consistent performance.",
            whyWrong: {
                1: "VPN limited by internet bandwidth and encryption overhead",
                2: "DataSync over internet subject to internet variability",
                3: "Transfer Acceleration still uses internet, not dedicated line"
            },
            examStrategy: "Direct Connect for dedicated bandwidth. VPN for encrypted connectivity. Transfer Acceleration for S3 uploads over internet."
        }
    },
    {
        id: 'perf_046',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A mobile app needs to sync user data across devices in real-time with offline capability.",
        question: "Which service provides the BEST performance for real-time sync with offline support?",
        options: [
            "AWS AppSync with conflict resolution",
            "DynamoDB with Streams and Lambda",
            "API Gateway with WebSocket APIs",
            "Cognito Sync with datasets"
        ],
        correct: 0,
        explanation: {
            correct: "AppSync provides real-time subscriptions with built-in offline support and conflict resolution.",
            whyWrong: {
                1: "DynamoDB Streams require custom offline implementation",
                2: "WebSocket APIs don't provide offline capability",
                3: "Cognito Sync is limited to 20MB per user"
            },
            examStrategy: "AppSync for real-time with offline. GraphQL subscriptions for efficiency. Built-in conflict resolution."
        }
    },
    {
        id: 'perf_047',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A recommendation engine needs to process 1 billion user interactions daily and generate recommendations in under 50ms.",
        question: "Which architecture provides sub-50ms recommendation latency at billion-scale?",
        options: [
            "SageMaker Inference with model caching and auto-scaling endpoints",
            "Pre-computed recommendations in DynamoDB with DAX",
            "Lambda with Provisioned Concurrency and ElastiCache",
            "Kinesis Analytics with ML algorithms"
        ],
        correct: 1,
        explanation: {
            correct: "Pre-computed recommendations in DynamoDB provide predictable single-digit millisecond latency, DAX adds microsecond caching.",
            whyWrong: {
                0: "SageMaker inference typically 100ms+ latency",
                2: "Lambda cold starts risk exceeding 50ms",
                3: "Kinesis Analytics for stream processing, not serving"
            },
            examStrategy: "Pre-compute when possible for lowest latency. Real-time ML adds latency. DynamoDB + DAX for predictable performance."
        }
    },
    {
        id: 'perf_048',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company needs to process 10 million images per day, extracting text and metadata from each image.",
        question: "Which service provides the MOST scalable image processing solution?",
        options: [
            "Amazon Rekognition with S3 batch operations",
            "Lambda functions with Textract API calls",
            "EC2 instances with OCR software",
            "SageMaker with custom vision models"
        ],
        correct: 0,
        explanation: {
            correct: "Rekognition with S3 batch operations can process millions of images in parallel without infrastructure management.",
            whyWrong: {
                1: "Lambda concurrency limits may throttle at this scale",
                2: "EC2 requires significant management and scaling logic",
                3: "SageMaker adds complexity for standard OCR tasks"
            },
            examStrategy: "Managed AI services for standard tasks. Batch operations for scale. Rekognition for image analysis, Textract for documents."
        }
    },
    {
        id: 'perf_049',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A website's database queries are slow because tables have grown to millions of rows.",
        question: "What is the FIRST optimization to try for slow queries on large tables?",
        options: [
            "Add appropriate indexes on frequently queried columns",
            "Migrate to a NoSQL database",
            "Upgrade to a larger RDS instance",
            "Implement sharding across multiple databases"
        ],
        correct: 0,
        explanation: {
            correct: "Indexes dramatically improve query performance on large tables by avoiding full table scans.",
            whyWrong: {
                1: "Migration is complex and may not solve the problem",
                2: "Larger instance won't help if queries scan entire tables",
                3: "Sharding adds significant complexity"
            },
            examStrategy: "Indexes first for query optimization. Analyze query patterns. Avoid premature optimization like sharding."
        }
    },
    {
        id: 'perf_050',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A gaming leaderboard needs to return top 100 players from 10 million users in under 50ms.",
        question: "Which data structure provides the FASTEST top-N queries?",
        options: [
            "Redis sorted sets with ZREVRANGE command",
            "DynamoDB with global secondary index on score",
            "RDS with indexed score column and LIMIT clause",
            "ElasticSearch with aggregation queries"
        ],
        correct: 0,
        explanation: {
            correct: "Redis sorted sets are specifically designed for leaderboards with O(log N) operations, returning top-100 in microseconds.",
            whyWrong: {
                1: "DynamoDB GSI scan would be slower for top-N",
                2: "RDS would need to sort 10 million rows",
                3: "ElasticSearch adds unnecessary complexity for simple ranking"
            },
            examStrategy: "Redis sorted sets for leaderboards. Purpose-built data structures. O(log N) beats O(N) at scale."
        }

    },

    {
        id: 'perf_051',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A real-time bidding platform needs to process 1 million bid requests per second with P99 latency under 50ms.",
        question: "Which architecture provides the required performance at this scale?",
        options: [
            "EC2 instances with placement groups, ElastiCache Redis cluster, and SR-IOV networking",
            "Lambda functions with maximum memory allocation",
            "API Gateway with caching enabled",
            "RDS with read replicas"
        ],
        correct: 0,
        explanation: {
            correct: "Placement groups minimize network latency, ElastiCache provides sub-millisecond data access, SR-IOV reduces network overhead.",
            whyWrong: {
                1: "Lambda has cold starts and concurrency limits at this scale",
                2: "API Gateway adds latency and has request rate limits",
                3: "RDS cannot achieve sub-50ms latency at this scale"
            },
            examStrategy: "For ultra-low latency: placement groups, in-memory caching, enhanced networking. Avoid service hops."
        }
    },
    {
        id: 'perf_052',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A genomics research platform needs to process 500TB of data through complex algorithms in under 4 hours.",
        question: "Which compute solution can process this data volume within the time constraint?",
        options: [
            "AWS Batch with Spot Fleet using compute-optimized instances and parallel processing",
            "Lambda functions with Step Functions orchestration",
            "Single large EC2 instance with maximum resources",
            "Fargate tasks with maximum CPU"
        ],
        correct: 0,
        explanation: {
            correct: "Batch with Spot Fleet provides massive parallel processing capacity at low cost, essential for 500TB in 4 hours.",
            whyWrong: {
                1: "Lambda 15-minute timeout and payload limits unsuitable for large data",
                2: "Single instance cannot process 500TB in 4 hours",
                3: "Fargate has resource limits insufficient for this scale"
            },
            examStrategy: "AWS Batch for large-scale parallel processing. Spot Fleet for cost-effective compute. Parallelize for big data."
        }
    },
    {
        id: 'perf_053',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A mobile app backend needs to serve personalized content to 50 million daily active users with <100ms response time globally.",
        question: "Which architecture delivers personalized content with global low latency?",
        options: [
            "CloudFront with Lambda@Edge for personalization and DynamoDB Global Tables",
            "Single region API with heavy caching",
            "Multiple regional deployments with database replication",
            "S3 with pre-generated content per user"
        ],
        correct: 0,
        explanation: {
            correct: "Lambda@Edge personalizes at edge locations for low latency, DynamoDB Global Tables provide local data access globally.",
            whyWrong: {
                1: "Single region cannot achieve <100ms globally",
                2: "Regional deployments add complexity without edge benefits",
                3: "Pre-generated content for 50M users is impractical"
            },
            examStrategy: "Edge computing for global low latency. Lambda@Edge for dynamic content at edge. Global Tables for distributed data."
        }
    },
    {
        id: 'perf_054',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's database queries are slow due to large table scans. The data is rarely updated but frequently read.",
        question: "What is the QUICKEST performance improvement for read-heavy workloads?",
        options: [
            "Create appropriate indexes on frequently queried columns",
            "Migrate to a NoSQL database",
            "Add more CPU to the database instance",
            "Implement application-level caching only"
        ],
        correct: 0,
        explanation: {
            correct: "Indexes dramatically improve query performance by avoiding full table scans, quick to implement.",
            whyWrong: {
                1: "Migration is complex and time-consuming",
                2: "CPU doesn't help with I/O-bound table scans",
                3: "Caching helps but doesn't address root cause"
            },
            examStrategy: "Indexes first for query optimization. Identify missing indexes before scaling. Read-heavy = aggressive indexing."
        }
    },
    {
        id: 'perf_055',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A video transcoding service needs to convert 10,000 hours of video daily across multiple formats and resolutions.",
        question: "Which architecture provides the BEST throughput for video transcoding?",
        options: [
            "AWS Elemental MediaConvert with job queue priorities and parallel processing",
            "EC2 instances with FFmpeg",
            "Lambda functions with container images",
            "Fargate tasks with custom transcoding"
        ],
        correct: 0,
        explanation: {
            correct: "MediaConvert is purpose-built for video transcoding at scale with automatic parallel processing and queue management.",
            whyWrong: {
                1: "EC2 with FFmpeg requires significant management overhead",
                2: "Lambda has 15-minute timeout, insufficient for video transcoding",
                3: "Fargate adds containerization overhead without transcoding optimization"
            },
            examStrategy: "Purpose-built services over custom solutions. MediaConvert for video transcoding. Managed services for complex workloads."
        }
    },
    {
        id: 'perf_056',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A financial modeling system requires 1 million Monte Carlo simulations completed in under 10 minutes.",
        question: "Which compute configuration can perform 1 million simulations in 10 minutes?",
        options: [
            "HPC cluster with C5n instances, Elastic Fabric Adapter, and ParallelCluster",
            "Lambda functions with maximum concurrency",
            "Single GPU-enabled instance",
            "Fargate with maximum CPU allocation"
        ],
        correct: 0,
        explanation: {
            correct: "HPC cluster with EFA provides the inter-node communication performance required for parallel Monte Carlo simulations.",
            whyWrong: {
                1: "Lambda lacks the sustained compute and coordination for HPC workloads",
                2: "Single instance cannot complete 1M simulations in 10 minutes",
                3: "Fargate lacks HPC networking capabilities"
            },
            examStrategy: "HPC workloads need specialized networking (EFA). ParallelCluster for managed HPC. C5n for compute-intensive work."
        }
    },
    {
        id: 'perf_057',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An analytics dashboard needs to query 50TB of historical data with sub-second response times for executive reports.",
        question: "Which solution provides sub-second query performance on 50TB?",
        options: [
            "Amazon Redshift with materialized views and result caching",
            "Athena with partitioned data",
            "RDS with read replicas",
            "DynamoDB with 50TB of data"
        ],
        correct: 0,
        explanation: {
            correct: "Redshift materialized views pre-compute results, result caching serves repeat queries instantly.",
            whyWrong: {
                1: "Athena typically takes seconds to minutes for 50TB queries",
                2: "RDS cannot efficiently handle 50TB analytical queries",
                3: "DynamoDB not designed for complex analytical queries"
            },
            examStrategy: "Redshift for large-scale analytics with performance requirements. Materialized views for pre-computation. Result caching for repeat queries."
        }
    },
    {
        id: 'perf_058',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "Users complain about slow image loading on a global e-commerce site. Images are currently served from S3 in us-east-1.",
        question: "What is the MOST effective solution to improve global image loading speed?",
        options: [
            "Implement CloudFront CDN with S3 as origin",
            "Enable S3 Transfer Acceleration",
            "Move S3 bucket to different region",
            "Compress images more aggressively"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront caches images at global edge locations, dramatically reducing latency for users worldwide.",
            whyWrong: {
                1: "Transfer Acceleration is for uploads, not downloads",
                2: "Different region only helps users in that region",
                3: "Compression helps but doesn't address geographic latency"
            },
            examStrategy: "CloudFront for global content delivery. Edge caching beats origin location. CDN first, then optimize content."
        }
    },
    {
        id: 'perf_059',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A machine learning inference API needs to handle 100,000 requests per second with P95 latency under 10ms.",
        question: "Which deployment provides the required inference performance?",
        options: [
            "SageMaker multi-model endpoints with GPU instances and model caching",
            "Lambda functions with provisioned concurrency",
            "ECS tasks with CPU instances",
            "Batch inference with S3"
        ],
        correct: 0,
        explanation: {
            correct: "SageMaker multi-model endpoints with GPUs provide the throughput and low latency required for high-volume inference.",
            whyWrong: {
                1: "Lambda lacks GPU support and has overhead for this volume",
                2: "CPU instances too slow for 10ms P95 at this scale",
                3: "Batch inference not suitable for real-time API"
            },
            examStrategy: "SageMaker for ML inference at scale. GPUs for low-latency inference. Multi-model endpoints for efficiency."
        }
    },
    {
        id: 'perf_060',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A global gaming platform needs to synchronize player actions across regions with maximum 20ms latency between any two players.",
        question: "Which architecture achieves global 20ms synchronization latency?",
        options: [
            "AWS Wavelength zones in major cities with 5G edge computing",
            "Single central server for consistency",
            "Regional servers with database replication",
            "CloudFront with WebSocket support"
        ],
        correct: 0,
        explanation: {
            correct: "Wavelength zones at 5G edges provide ultra-low latency required for 20ms global synchronization.",
            whyWrong: {
                1: "Central server cannot achieve 20ms globally due to physics",
                2: "Regional replication adds too much latency",
                3: "CloudFront WebSocket doesn't provide computation at edge"
            },
            examStrategy: "Wavelength for ultra-low latency at network edge. 5G edge computing for gaming. Physics limits require edge presence."
        }
    },
    {
        id: 'perf_061',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A log analysis system needs to search through 1PB of logs with query results returned in under 30 seconds.",
        question: "Which solution provides fast search across 1PB of logs?",
        options: [
            "Amazon OpenSearch with UltraWarm storage and hot-warm architecture",
            "S3 with Athena queries",
            "CloudWatch Logs Insights",
            "RDS with full-text search"
        ],
        correct: 0,
        explanation: {
            correct: "OpenSearch with UltraWarm provides cost-effective storage with hot data in memory for fast queries on massive datasets.",
            whyWrong: {
                1: "Athena on 1PB would take minutes to hours",
                2: "CloudWatch Logs expensive and slower at 1PB scale",
                3: "RDS cannot handle 1PB of log data"
            },
            examStrategy: "OpenSearch for log analytics at scale. Hot-warm architecture for cost-performance balance. UltraWarm for historical data."
        }
    },
    {
        id: 'perf_062',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A web application serves the same content repeatedly to thousands of users, causing high server load.",
        question: "What is the SIMPLEST way to reduce server load for repeated content?",
        options: [
            "Implement caching headers and CloudFront",
            "Add more servers",
            "Upgrade to larger instances",
            "Rewrite application code"
        ],
        correct: 0,
        explanation: {
            correct: "Caching headers with CloudFront serves repeated content from cache, eliminating server load.",
            whyWrong: {
                1: "Adding servers increases cost without solving root cause",
                2: "Larger instances still process redundant requests",
                3: "Code rewrite unnecessary when caching solves the issue"
            },
            examStrategy: "Cache first before scaling. CDN for static and cacheable dynamic content. Caching headers control cache behavior."
        }
    },
    {
        id: 'perf_063',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A social media platform needs to generate and serve millions of timeline feeds with personalized content in real-time.",
        question: "Which architecture provides the BEST performance for timeline generation?",
        options: [
            "Pre-computed timelines in DynamoDB with real-time updates via DynamoDB Streams",
            "Generate timelines on every request",
            "Cache complete timelines in ElastiCache",
            "Store all posts in S3 and filter client-side"
        ],
        correct: 0,
        explanation: {
            correct: "Pre-computing timelines provides instant serving while Streams enable real-time updates for new content.",
            whyWrong: {
                1: "On-demand generation too slow for user experience",
                2: "Caching entire timelines wastes memory for inactive users",
                3: "Client-side filtering doesn't scale and wastes bandwidth"
            },
            examStrategy: "Pre-compute when possible. Push model for timeline systems. DynamoDB Streams for real-time updates."
        }
    },
    {
        id: 'perf_064',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A scientific simulation requires 100 GPU nodes to communicate with each other with less than 1 microsecond latency.",
        question: "Which networking configuration achieves sub-microsecond latency between GPU nodes?",
        options: [
            "P4d instances with EFA and GPUDirect RDMA in cluster placement group",
            "G4 instances with enhanced networking",
            "Lambda with GPU container support",
            "Multiple regions for redundancy"
        ],
        correct: 0,
        explanation: {
            correct: "P4d with EFA and GPUDirect RDMA enables GPU-to-GPU communication bypassing CPU, achieving sub-microsecond latency.",
            whyWrong: {
                1: "G4 instances don't support GPUDirect RDMA",
                2: "Lambda doesn't support GPU or sub-microsecond networking",
                3: "Multiple regions increase latency, not reduce it"
            },
            examStrategy: "P4d for highest GPU performance. GPUDirect for GPU-to-GPU communication. Cluster placement for minimum latency."
        }
    },
    {
        id: 'perf_065',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An e-commerce search needs to return results from a catalog of 100 million products in under 50ms.",
        question: "Which search solution provides sub-50ms query latency for 100M products?",
        options: [
            "OpenSearch with dedicated master nodes and NVMe storage",
            "RDS with LIKE queries",
            "DynamoDB scan operations",
            "S3 Select queries"
        ],
        correct: 0,
        explanation: {
            correct: "OpenSearch with NVMe storage provides the indexing and query performance needed for sub-50ms searches on large catalogs.",
            whyWrong: {
                1: "RDS LIKE queries are too slow for 100M products",
                2: "DynamoDB scans are inefficient and slow",
                3: "S3 Select not designed for product search"
            },
            examStrategy: "OpenSearch for full-text search at scale. NVMe storage for performance. Purpose-built search over database queries."
        }
    },
    {
        id: 'perf_066',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's Lambda functions are experiencing cold starts that impact user experience.",
        question: "What is the MOST effective way to eliminate Lambda cold starts?",
        options: [
            "Configure provisioned concurrency for the Lambda functions",
            "Increase Lambda memory allocation",
            "Use smaller deployment packages",
            "Switch to different runtime"
        ],
        correct: 0,
        explanation: {
            correct: "Provisioned concurrency keeps Lambda functions warm and ready, eliminating cold starts entirely.",
            whyWrong: {
                1: "Memory doesn't eliminate cold starts, just reduces them slightly",
                2: "Smaller packages help but don't eliminate cold starts",
                3: "Runtime changes provide marginal improvements"
            },
            examStrategy: "Provisioned concurrency eliminates cold starts. Higher cost but guaranteed performance. Use for latency-sensitive functions."
        }
    },
    {
        id: 'perf_067',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A real-time analytics platform needs to process 1 million events per second and query the last 24 hours of data with sub-second latency.",
        question: "Which architecture handles both ingestion and queries at this scale?",
        options: [
            "Kinesis Data Streams → Kinesis Analytics → ElastiCache for recent data, S3 for historical",
            "Direct writes to RDS with indexing",
            "SQS to Lambda to DynamoDB",
            "API Gateway to S3"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis handles million events/sec ingestion, Analytics processes in real-time, ElastiCache serves recent data with sub-second latency.",
            whyWrong: {
                1: "RDS cannot handle 1M writes per second",
                2: "Lambda concurrency limits prevent this scale",
                3: "API Gateway has rate limits below 1M/sec"
            },
            examStrategy: "Streaming for high-volume ingestion. In-memory for low-latency queries. Separate ingestion from serving."
        }
    },
    {
        id: 'perf_068',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A cryptocurrency exchange needs to match orders with latency under 10 microseconds for high-frequency trading.",
        question: "Which architecture achieves 10-microsecond order matching?",
        options: [
            "FPGA-accelerated EC2 F1 instances with kernel bypass networking",
            "Lambda with maximum memory",
            "Fargate with dedicated resources",
            "RDS with stored procedures"
        ],
        correct: 0,
        explanation: {
            correct: "FPGA acceleration on F1 instances provides hardware-level performance with kernel bypass for ultra-low latency trading.",
            whyWrong: {
                1: "Lambda has millisecond-level overhead",
                2: "Fargate has container overhead incompatible with microseconds",
                3: "RDS latency measured in milliseconds, not microseconds"
            },
            examStrategy: "FPGA for ultra-low latency. Kernel bypass for network performance. Hardware acceleration when software isn't enough."
        }
    },
    {
        id: 'perf_069',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A content recommendation engine needs to serve personalized recommendations to 10 million concurrent users.",
        question: "Which architecture scales to 10 million concurrent users efficiently?",
        options: [
            "Pre-computed recommendations in DynamoDB with DAX caching layer",
            "Real-time ML inference for each request",
            "Single large RDS instance",
            "S3 static files per user"
        ],
        correct: 0,
        explanation: {
            correct: "Pre-computed recommendations in DynamoDB scale horizontally, DAX provides microsecond latency for millions of users.",
            whyWrong: {
                1: "Real-time inference doesn't scale to 10M concurrent users",
                2: "Single RDS instance has connection and performance limits",
                3: "Managing millions of S3 files is impractical"
            },
            examStrategy: "Pre-compute for scale. DynamoDB for horizontal scaling. DAX for microsecond latency. Avoid real-time computation at scale."
        }
    },
    {
        id: 'perf_070',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company needs to improve their database performance. Most queries search by customer_id and order_date.",
        question: "What is the MOST effective way to optimize these queries?",
        options: [
            "Create a composite index on (customer_id, order_date)",
            "Create separate indexes on each column",
            "Increase database CPU",
            "Add more database replicas"
        ],
        correct: 0,
        explanation: {
            correct: "Composite index on both columns optimizes queries that filter by customer_id and optionally by order_date.",
            whyWrong: {
                1: "Separate indexes less efficient for combined queries",
                2: "CPU doesn't help with I/O-bound index lookups",
                3: "Replicas help with read scaling but not individual query performance"
            },
            examStrategy: "Composite indexes for multi-column queries. Index order matters. Most selective column first."
        }
    },
    {
        id: 'perf_071',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A data warehouse needs to run complex analytical queries on 10 years of data while maintaining fast performance for recent data queries.",
        question: "Which Redshift feature optimizes performance for this access pattern?",
        options: [
            "Automatic table optimization with sort keys on date columns",
            "No optimization needed",
            "Manual vacuuming only",
            "Increase cluster size"
        ],
        correct: 0,
        explanation: {
            correct: "Automatic table optimization with date-based sort keys ensures recent data queries scan minimal blocks for fastest performance.",
            whyWrong: {
                1: "No optimization leads to poor performance",
                2: "Manual vacuuming alone doesn't optimize for access patterns",
                3: "Cluster size doesn't optimize data layout"
            },
            examStrategy: "Sort keys crucial for Redshift performance. Date-based sorting for time-series data. Automatic optimization reduces management."
        }
    },
    {
        id: 'perf_072',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A video game needs to update 1 million player positions 60 times per second with global state consistency.",
        question: "Which architecture handles 60 million position updates per second?",
        options: [
            "Custom UDP protocol with EC2 bare metal instances and SR-IOV",
            "WebSockets with API Gateway",
            "GraphQL subscriptions",
            "REST API with caching"
        ],
        correct: 0,
        explanation: {
            correct: "Custom UDP on bare metal with SR-IOV provides the raw performance needed for 60M updates/sec without protocol overhead.",
            whyWrong: {
                1: "API Gateway WebSockets can't handle this volume",
                2: "GraphQL adds too much overhead",
                3: "REST is request-response, not suitable for streaming updates"
            },
            examStrategy: "Custom protocols for extreme performance. Bare metal for predictable performance. UDP for minimum overhead."
        }
    },
    {
        id: 'perf_073',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A news aggregator needs to fetch and process content from 10,000 RSS feeds every 5 minutes.",
        question: "Which architecture efficiently processes 10,000 feeds in parallel?",
        options: [
            "Step Functions with Map state for parallel Lambda execution",
            "Single EC2 instance with threading",
            "Sequential Lambda invocations",
            "SQS with single consumer"
        ],
        correct: 0,
        explanation: {
            correct: "Step Functions Map state orchestrates parallel Lambda executions, processing thousands of feeds simultaneously.",
            whyWrong: {
                1: "Single instance threading has resource limits",
                2: "Sequential processing too slow for 10,000 feeds",
                3: "Single consumer creates bottleneck"
            },
            examStrategy: "Step Functions Map state for massive parallelism. Lambda for stateless parallel processing. Orchestration for coordination."
        }
    },
    {
        id: 'perf_074',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "Users report slow application performance during peak hours. The application makes many database queries per page load.",
        question: "What is the QUICKEST way to improve performance during peak hours?",
        options: [
            "Implement query result caching with ElastiCache",
            "Rewrite all database queries",
            "Migrate to a NoSQL database",
            "Add database indexes only"
        ],
        correct: 0,
        explanation: {
            correct: "ElastiCache provides immediate performance improvement by serving cached results, reducing database load during peaks.",
            whyWrong: {
                1: "Query rewriting takes significant time",
                2: "Migration is complex and risky",
                3: "Indexes help but caching provides more immediate relief"
            },
            examStrategy: "Caching for quick wins. ElastiCache for database offloading. Cache before optimize before scale."
        }
    },
    {
        id: 'perf_075',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A ride-sharing app needs to match drivers with riders based on real-time location with sub-second response.",
        question: "Which solution provides sub-second geospatial matching?",
        options: [
            "ElastiCache with Redis geospatial commands and Pub/Sub",
            "RDS with PostGIS extension",
            "DynamoDB with geohash indexes",
            "S3 with location files"
        ],
        correct: 0,
        explanation: {
            correct: "Redis geospatial commands provide optimized proximity searches with sub-millisecond performance, Pub/Sub for real-time updates.",
            whyWrong: {
                1: "PostGIS queries slower than in-memory Redis",
                2: "DynamoDB geohash requires application logic",
                3: "S3 not suitable for real-time matching"
            },
            examStrategy: "Redis for geospatial operations. In-memory for sub-second latency. Purpose-built commands over custom logic."
        }
    },
    {
        id: 'perf_076',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A blockchain analytics platform needs to process 50TB of transaction graphs with complex traversal queries in seconds.",
        question: "Which database provides the BEST performance for large-scale graph traversals?",
        options: [
            "Neptune with instance store and read replicas across AZs",
            "DynamoDB with adjacency lists",
            "RDS with recursive CTEs",
            "DocumentDB with references"
        ],
        correct: 0,
        explanation: {
            correct: "Neptune is purpose-built for graph workloads, instance store provides SSD performance for 50TB graph traversals.",
            whyWrong: {
                1: "DynamoDB adjacency lists require multiple queries",
                2: "RDS recursive CTEs inefficient for deep traversals",
                3: "DocumentDB not optimized for graph operations"
            },
            examStrategy: "Neptune for graph workloads. Purpose-built beats general-purpose. Instance store for performance-critical data."
        }
    },
    {
        id: 'perf_077',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A music streaming service needs to serve millions of concurrent audio streams with minimal buffering.",
        question: "Which architecture provides the BEST streaming performance?",
        options: [
            "CloudFront with S3 origin and byte-range requests",
            "EC2 instances with load balancing",
            "Lambda functions serving audio chunks",
            "EFS with multiple mount points"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront caches audio at edge locations globally, byte-range requests enable efficient streaming without full file downloads.",
            whyWrong: {
                1: "EC2 requires significant infrastructure management",
                2: "Lambda not optimized for streaming large files",
                3: "EFS has higher latency than CloudFront edge caches"
            },
            examStrategy: "CloudFront for media streaming. Byte-range requests for efficient delivery. Edge caching for global performance."
        }
    },
    {
        id: 'perf_078',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's application is slow because it loads entire large datasets into memory for processing.",
        question: "Which approach BEST improves performance for large dataset processing?",
        options: [
            "Stream processing with pagination to process data in chunks",
            "Increase instance memory to fit entire dataset",
            "Compress data before loading",
            "Use faster storage"
        ],
        correct: 0,
        explanation: {
            correct: "Streaming and pagination process data incrementally, reducing memory usage and improving performance.",
            whyWrong: {
                1: "Increasing memory is expensive and has limits",
                2: "Compression still requires decompression in memory",
                3: "Storage speed doesn't address memory bottleneck"
            },
            examStrategy: "Stream processing for large data. Pagination prevents memory exhaustion. Process incrementally, not all at once."
        }
    },
    {
        id: 'perf_079',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An IoT platform needs to aggregate data from 1 million devices in real-time for dashboard display.",
        question: "Which architecture provides real-time aggregation for millions of devices?",
        options: [
            "Kinesis Analytics with tumbling windows and output to ElastiCache",
            "Store all data in RDS and query on demand",
            "Lambda processing each message individually",
            "Batch processing every hour"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis Analytics performs streaming aggregation in tumbling windows, ElastiCache serves pre-aggregated results instantly.",
            whyWrong: {
                1: "RDS queries on millions of records too slow for real-time",
                2: "Individual Lambda processing doesn't provide aggregation",
                3: "Hourly batch not real-time"
            },
            examStrategy: "Streaming analytics for real-time aggregation. Tumbling windows for time-based aggregates. Pre-aggregate for dashboard performance."
        }
    },
    {
        id: 'perf_080',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A metaverse platform needs to render 3D environments for 100,000 concurrent users with ray tracing enabled.",
        question: "Which architecture delivers ray-traced 3D rendering at this scale?",
        options: [
            "NICE DCV with G4ad instances and NVIDIA CloudXR streaming",
            "Client-side rendering only",
            "Lambda functions with 3D libraries",
            "S3 with pre-rendered scenes"
        ],
        correct: 0,
        explanation: {
            correct: "NICE DCV provides high-performance streaming, G4ad instances with AMD GPUs handle ray tracing at scale, CloudXR optimizes delivery.",
            whyWrong: {
                1: "Client devices lack power for ray tracing",
                2: "Lambda doesn't support GPU acceleration",
                3: "Pre-rendered scenes aren't interactive"
            },
            examStrategy: "Cloud rendering for compute-intensive graphics. GPU instances for ray tracing. Streaming protocols for delivery."
        }
    },
    {
        id: 'perf_081',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A financial data platform needs to join and analyze data from 50 different sources in near real-time.",
        question: "Which service provides the BEST performance for multi-source data integration?",
        options: [
            "AWS Glue with in-memory Apache Spark and job bookmarks",
            "Lambda functions with custom logic",
            "RDS with federated queries",
            "Manual ETL scripts on EC2"
        ],
        correct: 0,
        explanation: {
            correct: "Glue provides managed Spark with in-memory processing for fast joins, job bookmarks track incremental processing.",
            whyWrong: {
                1: "Lambda has memory and time limits for complex joins",
                2: "Federated queries add network latency",
                3: "Manual scripts lack optimization and management"
            },
            examStrategy: "Glue for managed ETL at scale. In-memory Spark for performance. Job bookmarks for incremental processing."
        }
    },
    {
        id: 'perf_082',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A website's homepage takes 10 seconds to load due to multiple sequential API calls.",
        question: "What is the BEST way to improve homepage load time?",
        options: [
            "Make API calls in parallel instead of sequential",
            "Increase server CPU",
            "Add more servers",
            "Increase network bandwidth"
        ],
        correct: 0,
        explanation: {
            correct: "Parallel API calls execute simultaneously, dramatically reducing total load time from sum to maximum of individual calls.",
            whyWrong: {
                1: "CPU doesn't help with network wait times",
                2: "More servers don't fix sequential call pattern",
                3: "Bandwidth rarely the bottleneck for API calls"
            },
            examStrategy: "Parallelize independent operations. Identify and eliminate sequential bottlenecks. Concurrent over sequential execution."
        }
    },
    {
        id: 'perf_083',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A video platform needs to generate thumbnails for 100,000 uploaded videos daily within 1 minute of upload.",
        question: "Which architecture provides fast thumbnail generation at scale?",
        options: [
            "S3 event triggers Lambda with parallel processing using AWS Batch for overflow",
            "Single EC2 instance processing sequentially",
            "Manual processing with scripts",
            "Store videos without thumbnails"
        ],
        correct: 0,
        explanation: {
            correct: "S3 events trigger immediate processing, Lambda handles normal load, Batch handles spikes with massive parallelism.",
            whyWrong: {
                1: "Sequential processing too slow for volume",
                2: "Manual processing doesn't scale",
                3: "No thumbnails impacts user experience"
            },
            examStrategy: "Event-driven for immediate processing. Lambda for serverless scale. Batch for overflow handling."
        }
    },
    {
        id: 'perf_084',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A scientific computing workload requires 100Gbps disk throughput for processing satellite imagery.",
        question: "Which storage configuration provides 100Gbps throughput?",
        options: [
            "Multiple io2 Block Express volumes in RAID 0 configuration",
            "Single EBS volume",
            "S3 with multipart upload",
            "EFS with Max I/O mode"
        ],
        correct: 0,
        explanation: {
            correct: "Multiple io2 Block Express volumes in RAID 0 aggregate throughput to achieve 100Gbps requirement.",
            whyWrong: {
                1: "Single volume limited to 4GBps (32Gbps)",
                2: "S3 has latency not suitable for compute workloads",
                3: "EFS Max I/O provides 10Gbps, not 100Gbps"
            },
            examStrategy: "RAID 0 for throughput aggregation. io2 Block Express for maximum performance. Multiple volumes overcome single volume limits."
        }
    },
    {
        id: 'perf_085',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An e-commerce platform needs to update inventory across 100 warehouses in real-time as orders are placed.",
        question: "Which architecture provides real-time inventory synchronization?",
        options: [
            "DynamoDB Global Tables with streams triggering Lambda for inventory updates",
            "Batch updates every hour",
            "Direct database writes to each warehouse",
            "Email notifications to warehouses"
        ],
        correct: 0,
        explanation: {
            correct: "Global Tables provide multi-region replication, Streams trigger Lambda for real-time inventory adjustments across all locations.",
            whyWrong: {
                1: "Hourly batches create inventory discrepancies",
                2: "Direct writes don't scale and lack coordination",
                3: "Email is not real-time or automated"
            },
            examStrategy: "DynamoDB Streams for real-time triggers. Global Tables for distributed data. Event-driven for immediate updates."
        }
    },
    {
        id: 'perf_086',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A mobile app makes the same API request hundreds of times per second for rarely-changing data.",
        question: "What is the MOST effective way to reduce redundant API calls?",
        options: [
            "Implement API Gateway caching with TTL",
            "Rate limit the mobile app",
            "Add more backend servers",
            "Block repeated requests"
        ],
        correct: 0,
        explanation: {
            correct: "API Gateway caching serves repeated requests from cache, eliminating backend calls while maintaining fresh data with TTL.",
            whyWrong: {
                1: "Rate limiting degrades user experience",
                2: "More servers still process redundant requests",
                3: "Blocking requests breaks app functionality"
            },
            examStrategy: "Cache at API Gateway for repeated requests. TTL balances freshness with performance. Caching beats scaling."
        }
    },
    {
        id: 'perf_087',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A machine learning pipeline needs to feature engineer 1TB of data with complex transformations before training.",
        question: "Which service provides the BEST performance for large-scale feature engineering?",
        options: [
            "SageMaker Processing with distributed Spark jobs",
            "Lambda functions with Step Functions",
            "EC2 with manual scripts",
            "Glue interactive sessions"
        ],
        correct: 0,
        explanation: {
            correct: "SageMaker Processing runs distributed Spark jobs optimized for ML feature engineering with managed infrastructure.",
            whyWrong: {
                1: "Lambda has 15-minute timeout and 10GB memory limit",
                2: "Manual EC2 requires significant management",
                3: "Glue interactive sessions better for development than production"
            },
            examStrategy: "SageMaker Processing for ML data preparation. Distributed Spark for TB-scale processing. Managed over self-managed."
        }
    },
    {
        id: 'perf_088',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A real-time video analytics system needs to process 1000 concurrent 4K video streams with object detection.",
        question: "Which architecture handles 1000 concurrent 4K streams with ML inference?",
        options: [
            "Kinesis Video Streams with SageMaker endpoints on GPU instances",
            "Lambda functions with Rekognition",
            "EC2 with OpenCV",
            "S3 with batch processing"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis Video Streams handles video ingestion at scale, SageMaker GPU endpoints provide the compute power for real-time 4K inference.",
            whyWrong: {
                1: "Rekognition has rate limits and costs for this volume",
                2: "EC2 management complex for 1000 streams",
                3: "Batch processing not real-time"
            },
            examStrategy: "Kinesis Video for video streaming. SageMaker for custom ML at scale. GPU for video ML inference."
        }
    },
    {
        id: 'perf_089',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A logistics platform needs to optimize delivery routes for 10,000 drivers every morning in under 5 minutes.",
        question: "Which compute solution can optimize 10,000 routes in 5 minutes?",
        options: [
            "AWS Batch with parallel optimization algorithms on compute-optimized instances",
            "Lambda functions with 1 function per driver",
            "Single large instance with threading",
            "Manual route planning"
        ],
        correct: 0,
        explanation: {
            correct: "Batch provides massive parallel compute for optimization algorithms, compute-optimized instances maximize performance per route.",
            whyWrong: {
                1: "10,000 concurrent Lambdas hit account limits",
                2: "Single instance insufficient for 10,000 optimizations in 5 minutes",
                3: "Manual planning impossible at this scale"
            },
            examStrategy: "AWS Batch for large-scale parallel computing. Compute-optimized for CPU-intensive algorithms. Parallel over sequential."
        }
    },
    {
        id: 'perf_090',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A web application becomes slow when generating PDF reports from database data.",
        question: "What is the BEST way to improve PDF generation performance?",
        options: [
            "Generate PDFs asynchronously with SQS and return download link",
            "Increase web server CPU",
            "Generate PDFs on client-side",
            "Limit report size"
        ],
        correct: 0,
        explanation: {
            correct: "Asynchronous generation via SQS prevents web server blocking, users get immediate response with link when ready.",
            whyWrong: {
                1: "CPU increase doesn't solve blocking issue",
                2: "Client-side lacks data access and processing power",
                3: "Limiting size reduces functionality"
            },
            examStrategy: "Async for long-running operations. Queue-based processing for heavy tasks. Don't block web servers."
        }
    },
    {
        id: 'perf_091',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A social network needs to deliver push notifications to 50 million users within 30 seconds of an event.",
        question: "Which architecture delivers notifications to 50M users in 30 seconds?",
        options: [
            "SNS with platform endpoints and batch publishing",
            "Individual API calls to each device",
            "Email notifications",
            "In-app polling only"
        ],
        correct: 0,
        explanation: {
            correct: "SNS handles mobile push at scale with batch publishing enabling millions of notifications in seconds.",
            whyWrong: {
                1: "Individual API calls too slow for 50M in 30 seconds",
                2: "Email has delivery delays",
                3: "Polling has latency and battery drain"
            },
            examStrategy: "SNS for mobile push at scale. Batch operations for mass delivery. Purpose-built over custom solutions."
        }
    },
    {
        id: 'perf_092',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A autonomous vehicle platform needs to process LIDAR data with 1ms latency for collision avoidance.",
        question: "Which edge computing solution provides 1ms processing latency?",
        options: [
            "AWS Outposts with local compute and Greengrass for edge ML",
            "Cloud-based processing with API Gateway",
            "Lambda@Edge functions",
            "Batch processing in cloud"
        ],
        correct: 0,
        explanation: {
            correct: "Outposts provides local compute eliminating network latency, Greengrass runs ML models at edge for 1ms response.",
            whyWrong: {
                1: "Cloud processing adds network latency exceeding 1ms",
                2: "Lambda@Edge still requires network round trip",
                3: "Batch processing not real-time"
            },
            examStrategy: "Edge computing for ultra-low latency. Outposts for on-premises AWS. Greengrass for edge ML inference."
        }
    },
    {
        id: 'perf_093',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "An analytics platform needs to join 10 billion rows from multiple tables for daily reports.",
        question: "Which solution provides the BEST performance for billion-row joins?",
        options: [
            "Redshift with distribution keys matching join columns",
            "RDS with standard indexes",
            "DynamoDB with scan operations",
            "Multiple Lambda functions"
        ],
        correct: 0,
        explanation: {
            correct: "Redshift distribution keys co-locate join data on same nodes, eliminating network transfer for massive performance gains.",
            whyWrong: {
                1: "RDS not optimized for billion-row analytical joins",
                2: "DynamoDB scans extremely expensive and slow",
                3: "Lambda memory insufficient for billion-row joins"
            },
            examStrategy: "Redshift for analytical joins at scale. Distribution keys crucial for join performance. Co-location eliminates network transfer."
        }
    },
    {
        id: 'perf_094',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's website loads slowly for international users, but performs well for US users.",
        question: "What is the PRIMARY cause and solution for this performance issue?",
        options: [
            "Geographic latency - implement CloudFront CDN",
            "Server capacity - add more servers",
            "Code bugs - fix application code",
            "Database issues - optimize queries"
        ],
        correct: 0,
        explanation: {
            correct: "Geographic distance causes latency for international users; CloudFront edge locations provide local content delivery.",
            whyWrong: {
                1: "Server capacity would affect all users equally",
                2: "Code bugs would affect all users",
                3: "Database issues would impact all users"
            },
            examStrategy: "Geographic latency requires edge solutions. CloudFront for global content delivery. Distance matters for performance."
        }
    },
    {
        id: 'perf_095',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A real-time gaming platform needs to maintain game state for 1 million concurrent players with instant updates.",
        question: "Which architecture provides instant state updates for millions of players?",
        options: [
            "ElastiCache Redis with Pub/Sub and cluster mode",
            "RDS with high IOPS",
            "S3 with versioning",
            "DynamoDB with eventually consistent reads"
        ],
        correct: 0,
        explanation: {
            correct: "Redis Pub/Sub provides instant message delivery, cluster mode scales to millions of connections with in-memory performance.",
            whyWrong: {
                1: "RDS connection limits prevent million concurrent connections",
                2: "S3 has latency unsuitable for instant updates",
                3: "Eventually consistent reads don't provide instant consistency"
            },
            examStrategy: "Redis Pub/Sub for real-time messaging. Cluster mode for horizontal scaling. In-memory for instant access."
        }
    },
    {
        id: 'perf_096',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A particle physics simulation requires 500 TFLOPS of sustained compute performance for 48 hours.",
        question: "Which instance configuration provides 500 TFLOPS sustained performance?",
        options: [
            "Multiple P4d.24xlarge instances with placement group",
            "Single largest CPU instance",
            "Lambda functions in parallel",
            "Fargate with maximum resources"
        ],
        correct: 0,
        explanation: {
            correct: "P4d.24xlarge provides 320 TFLOPS each, multiple instances in placement group achieve 500+ TFLOPS with network optimization.",
            whyWrong: {
                1: "CPU instances provide ~10 TFLOPS maximum",
                2: "Lambda cannot sustain for 48 hours",
                3: "Fargate lacks GPU support"
            },
            examStrategy: "P4d for maximum GPU compute. TFLOPS requires GPU acceleration. Placement groups for multi-instance performance."
        }
    },
    {
        id: 'perf_097',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A document processing system needs to extract text from 1 million PDF files daily.",
        question: "Which service provides the BEST performance for large-scale document processing?",
        options: [
            "Amazon Textract with asynchronous operations and S3 batch processing",
            "Lambda functions with PDF libraries",
            "EC2 with OCR software",
            "Manual processing"
        ],
        correct: 0,
        explanation: {
            correct: "Textract provides managed OCR optimized for scale, asynchronous operations handle large volumes efficiently.",
            whyWrong: {
                1: "Lambda has memory and timeout constraints for PDFs",
                2: "EC2 OCR requires significant management",
                3: "Manual processing impossible at this scale"
            },
            examStrategy: "Textract for document processing at scale. Async operations for large batches. Managed services over custom OCR."
        }
    },
    {
        id: 'perf_098',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's batch job takes 8 hours to complete. Analysis shows 90% of time is spent waiting for I/O operations.",
        question: "What is the MOST effective optimization for I/O-bound batch jobs?",
        options: [
            "Process multiple files in parallel to maximize I/O utilization",
            "Upgrade to faster CPUs",
            "Add more memory",
            "Use larger instance types"
        ],
        correct: 0,
        explanation: {
            correct: "Parallel processing overlaps I/O wait times, dramatically reducing total execution time for I/O-bound work.",
            whyWrong: {
                1: "Faster CPUs don't help with I/O waiting",
                2: "Memory doesn't improve I/O wait times",
                3: "Larger instances don't necessarily improve I/O"
            },
            examStrategy: "Identify bottleneck type (CPU vs I/O). Parallelize I/O operations. Overlap wait times with processing."
        }
    },
    {
        id: 'perf_099',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A search engine needs to index 100 million web pages with full-text search capability updated hourly.",
        question: "Which architecture provides scalable indexing with hourly updates?",
        options: [
            "OpenSearch with cluster auto-scaling and index lifecycle management",
            "RDS with full-text indexes",
            "DynamoDB with scan operations",
            "S3 with metadata tags"
        ],
        correct: 0,
        explanation: {
            correct: "OpenSearch scales horizontally for large indices, lifecycle management optimizes storage, auto-scaling handles load variations.",
            whyWrong: {
                1: "RDS full-text doesn't scale to 100M documents efficiently",
                2: "DynamoDB scans extremely inefficient for full-text search",
                3: "S3 tags not designed for full-text search"
            },
            examStrategy: "OpenSearch for full-text search at scale. Horizontal scaling for large indices. Lifecycle management for cost-performance."
        }
    },
    {
        id: 'perf_100',
        domain: "Domain 3: Design High-Performing Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A weather simulation needs to process 1PB of atmospheric data through complex models in 2 hours for disaster prediction.",
        question: "Which HPC architecture can process 1PB through complex models in 2 hours?",
        options: [
            "ParallelCluster with 1000+ compute nodes, FSx for Lustre, and MPI with EFA",
            "Single powerful instance",
            "Lambda functions with S3",
            "EMR cluster with Spark"
        ],
        correct: 0,
        explanation: {
            correct: "ParallelCluster manages massive HPC clusters, FSx Lustre provides PB-scale parallel filesystem, EFA enables efficient MPI communication.",
            whyWrong: {
                1: "No single instance can process 1PB in 2 hours",
                2: "Lambda not suitable for tightly-coupled HPC",
                3: "EMR/Spark not optimized for atmospheric modeling"
            },
            examStrategy: "ParallelCluster for HPC workloads. FSx Lustre for HPC storage. EFA for MPI performance. Scale-out for PB processing."
        }
    }

   ],

    // Domain 4: Design Cost-Optimized Architectures (100 questions - 20%)
    cost: [
        {
            id: 'cost_001',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company runs development and test environments that are only used during business hours (8 AM to 6 PM, Monday-Friday). The environments use EC2, RDS, and ALB.",
            question: "Which approach provides the MOST cost savings for these environments?",
            options: [
                "AWS Instance Scheduler to stop/start resources based on schedule",
                "Reserved Instances with partial upfront payment",
                "Spot Instances for all environment resources",
                "Savings Plans with compute savings"
            ],
            correct: 0,
            explanation: {
                correct: "Instance Scheduler can stop resources during off-hours, saving ~70% of costs for resources used only 25% of the time.",
                whyWrong: {
                    1: "Reserved Instances charge for 24/7 usage, not cost-effective for partial use",
                    2: "Spot Instances can be terminated and aren't suitable for RDS/ALB",
                    3: "Savings Plans still charge for 24/7 commitment"
                },
                examStrategy: "For intermittent workloads, stop/start resources. For 24/7 workloads, use Reserved Instances or Savings Plans."
            }
        },
        {
            id: 'cost_002',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company has 1PB of data in S3 that's accessed frequently for the first 30 days, occasionally for 90 days, and rarely after that but must be retained for 7 years for compliance.",
            question: "Which S3 storage class transition policy minimizes costs while meeting requirements?",
            options: [
                "Standard → Standard-IA after 30 days → Glacier Flexible after 90 days → Glacier Deep Archive after 180 days",
                "Standard → Intelligent-Tiering immediately, let AWS manage transitions",
                "Standard → Glacier Instant Retrieval after 30 days → Glacier Deep Archive after 90 days",
                "Standard → One Zone-IA after 30 days → Glacier Flexible after 90 days"
            ],
            correct: 0,
            explanation: {
                correct: "This progression matches access patterns: Standard-IA for occasional access, Glacier Flexible for rare access, Deep Archive for long-term compliance storage.",
                whyWrong: {
                    1: "Intelligent-Tiering has monitoring fees that add up for 1PB of data",
                    2: "Glacier Instant is more expensive than Standard-IA for occasional access",
                    3: "One Zone-IA risks data loss, not suitable for compliance data"
                },
                examStrategy: "Match S3 storage classes to access patterns. Deep Archive for compliance/archive. Consider Intelligent-Tiering fees at scale."
            }
        },
        {
            id: 'cost_003',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A startup needs to run a web application with predictable traffic patterns. They want to minimize costs over a 3-year period.",
            question: "Which EC2 purchasing option provides the LOWEST total cost over 3 years?",
            options: [
                "3-year All Upfront Reserved Instances",
                "3-year Compute Savings Plans",
                "1-year No Upfront Reserved Instances renewed annually",
                "On-Demand Instances with auto-scaling"
            ],
            correct: 0,
            explanation: {
                correct: "3-year All Upfront Reserved Instances provide the maximum discount (up to 72%) for predictable, steady-state workloads.",
                whyWrong: {
                    1: "Compute Savings Plans offer less discount than All Upfront RIs",
                    2: "1-year RIs have lower discounts and renewal overhead",
                    3: "On-Demand is the most expensive option over 3 years"
                },
                examStrategy: "For maximum savings with predictable workloads: All Upfront > Partial Upfront > No Upfront. Longer terms save more."
            }
        },
        {
            id: 'cost_004',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company needs to transfer 500TB of data from on-premises to S3 for a one-time migration.",
            question: "What is the MOST cost-effective method to transfer this data?",
            options: [
                "AWS Direct Connect with data transfer",
                "AWS Snow Family devices",
                "AWS DataSync over internet",
                "S3 Transfer Acceleration"
            ],
            correct: 1,
            explanation: {
                correct: "Snow Family devices provide the most cost-effective transfer for large one-time migrations, avoiding ongoing network costs.",
                whyWrong: {
                    0: "Direct Connect has high setup costs not justified for one-time transfer",
                    2: "500TB over internet would take months and incur ISP charges",
                    3: "Transfer Acceleration charges per GB add up significantly for 500TB"
                },
                examStrategy: "Snow Family for large one-time transfers (>10TB). Direct Connect for ongoing transfers. DataSync for regular sync."
            }
        },
        {
            id: 'cost_005',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A media company has multiple AWS accounts with varying EC2 usage patterns. They want to optimize costs across all accounts.",
            question: "Which strategy provides the BEST cost optimization across multiple accounts?",
            options: [
                "AWS Organizations with consolidated billing and Compute Savings Plans",
                "Reserved Instances in each account separately",
                "Spot Instances for all non-critical workloads",
                "AWS Control Tower with Service Control Policies"
            ],
            correct: 0,
            explanation: {
                correct: "Consolidated billing aggregates usage for volume discounts, and Compute Savings Plans provide flexibility across accounts.",
                whyWrong: {
                    1: "Separate RIs in each account don't benefit from aggregated usage",
                    2: "Spot alone doesn't optimize On-Demand or Reserved capacity costs",
                    3: "Control Tower provides governance, not cost optimization"
                },
                examStrategy: "Consolidated billing for volume discounts. Savings Plans for flexibility. Reserved Instances for specific workloads."
            }
        },
        {
            id: 'cost_006',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "An analytics company processes 100TB of log data daily. Data must be queryable for 30 days, then archived for 1 year for compliance.",
            question: "Which architecture provides the LOWEST cost for this data lifecycle?",
            options: [
                "S3 Standard → Athena for queries → S3 Glacier after 30 days",
                "Kinesis Data Firehose → S3 → Redshift Spectrum → Glacier",
                "CloudWatch Logs → Elasticsearch → S3 Glacier",
                "EMR with HDFS → S3 Standard-IA → Glacier Deep Archive"
            ],
            correct: 0,
            explanation: {
                correct: "S3 with Athena provides serverless querying without infrastructure costs, and Glacier provides low-cost archival.",
                whyWrong: {
                    1: "Redshift Spectrum adds unnecessary costs for log analysis",
                    2: "Elasticsearch cluster costs are high for 100TB daily",
                    3: "EMR cluster costs are significant compared to serverless Athena"
                },
                examStrategy: "Serverless analytics (Athena) for cost optimization. Avoid running clusters 24/7 when possible. Glacier for archives."
            }
        },
        {
            id: 'cost_007',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company's production database has 2TB of frequently accessed data and 18TB of historical data accessed once per month.",
            question: "Which database strategy minimizes costs while maintaining performance?",
            options: [
                "Keep hot data in Aurora, move cold data to S3 with Athena for queries",
                "Use Aurora with 20TB storage and read replicas",
                "Implement DynamoDB with auto-scaling for all data",
                "Use Redshift for all data with reserved nodes"
            ],
            correct: 0,
            explanation: {
                correct: "Separating hot/cold data reduces Aurora storage costs while S3+Athena provides cost-effective querying for historical data.",
                whyWrong: {
                    1: "Storing 18TB of rarely accessed data in Aurora is expensive",
                    2: "DynamoDB would be extremely expensive for 20TB of data",
                    3: "Redshift is overkill and expensive for this use case"
                },
                examStrategy: "Separate hot and cold data. Use appropriate storage for access patterns. S3+Athena for cold data analytics."
            }
        },
        {
            id: 'cost_008',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to reduce their monthly AWS bill, which is primarily EC2 and RDS costs.",
            question: "What should be the FIRST step in cost optimization?",
            options: [
                "Purchase Reserved Instances immediately",
                "Use AWS Cost Explorer to analyze usage patterns",
                "Terminate all development environments",
                "Switch everything to Spot Instances"
            ],
            correct: 1,
            explanation: {
                correct: "Cost Explorer helps identify optimization opportunities by analyzing actual usage patterns before making purchasing decisions.",
                whyWrong: {
                    0: "Purchasing RIs without analysis might lead to wrong instance types or terms",
                    2: "Terminating resources without analysis might impact operations",
                    3: "Spot Instances aren't suitable for all workloads"
                },
                examStrategy: "Always analyze before optimizing. Cost Explorer and Trusted Advisor are starting points for cost optimization."
            }
        },
        {
            id: 'cost_009',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A SaaS application serves global customers with varying traffic patterns across regions. Most traffic comes from US and EU.",
            question: "Which architecture minimizes costs while maintaining global availability?",
            options: [
                "Full deployment in US and EU regions, CloudFront for other regions",
                "Deploy in all regions with auto-scaling",
                "Single region deployment with CloudFront global distribution",
                "Use AWS Local Zones in major cities"
            ],
            correct: 0,
            explanation: {
                correct: "Deploying in primary traffic regions reduces latency while CloudFront serves other regions cost-effectively.",
                whyWrong: {
                    1: "Deploying in all regions is expensive with low ROI for low-traffic regions",
                    2: "Single region might not meet latency requirements for EU",
                    3: "Local Zones are expensive and not necessary for this use case"
                },
                examStrategy: "Deploy compute where your users are. Use CloudFront for global reach. Don't over-provision in low-traffic regions."
            }
        },
        {
            id: 'cost_010',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company processes nightly batch jobs that can take 2-8 hours. Jobs can be interrupted and resumed. The workload runs every night.",
            question: "Which compute strategy provides the OPTIMAL cost-performance balance?",
            options: [
                "Spot Fleet with mixed instance types and on-demand capacity for critical components",
                "Reserved Instances sized for peak workload",
                "On-Demand instances with auto-scaling",
                "Lambda functions with Step Functions orchestration"
            ],
            correct: 0,
            explanation: {
                correct: "Spot Fleet provides up to 90% savings for interruptible workloads, with on-demand ensuring critical components complete.",
                whyWrong: {
                    1: "RIs would be underutilized during shorter job runs",
                    2: "On-Demand is most expensive for nightly batch jobs",
                    3: "Lambda 15-minute timeout not suitable for 2-8 hour jobs"
                },
                examStrategy: "Spot for batch/interruptible workloads. Mix Spot with On-Demand for reliability. RIs for 24/7 workloads."
            }
        },
        {
            id: 'cost_011',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company runs 50 EC2 instances for internal applications used only during business hours (40 hours/week). They're currently using On-Demand instances.",
            question: "Which purchasing strategy would provide the GREATEST cost savings?",
            options: [
                "Convert to Scheduled Reserved Instances for business hours",
                "Use AWS Instance Scheduler to stop instances after hours",
                "Purchase Standard Reserved Instances with 1-year term",
                "Switch to Spot Instances with persistent requests"
            ],
            correct: 1,
            explanation: {
                correct: "Instance Scheduler can stop instances for 128 hours/week (76% of time), saving ~76% compared to running 24/7.",
                whyWrong: {
                    0: "Scheduled RIs are discontinued, no longer available",
                    2: "Standard RIs charge 24/7, no savings for partial use",
                    3: "Spot Instances unsuitable for scheduled business applications"
                },
                examStrategy: "For predictable part-time use: stop/start instances. For 24/7 use: Reserved Instances or Savings Plans."
            }
        },
        {
            id: 'cost_012',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company stores 2PB of genomic research data. Data older than 1 year is accessed once per quarter for compliance audits. New data is analyzed daily for 30 days.",
            question: "Which S3 storage strategy minimizes costs while meeting access requirements?",
            options: [
                "S3 Intelligent-Tiering for all data",
                "S3 Standard for 30 days → S3 Standard-IA → Glacier Instant Retrieval after 1 year",
                "S3 Standard for 30 days → Glacier Flexible Retrieval after 1 year",
                "S3 One Zone-IA for all data with lifecycle policies"
            ],
            correct: 1,
            explanation: {
                correct: "This tiering matches access patterns: Standard for frequent access, Standard-IA for occasional, Glacier Instant for quarterly access with immediate retrieval.",
                whyWrong: {
                    0: "Intelligent-Tiering has monitoring charges that add up for 2PB",
                    2: "Glacier Flexible has retrieval delays (1-12 hours) impacting audits",
                    3: "One Zone-IA risks data loss for critical research data"
                },
                examStrategy: "Match storage class to access pattern. Consider retrieval time requirements. Glacier Instant = immediate, Flexible = hours, Deep = hours/days."
            }
        },
        {
            id: 'cost_013',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A startup needs to minimize RDS costs for their development environment which requires a 4-hour restore time objective.",
            question: "Which backup strategy provides the LOWEST cost while meeting the RTO?",
            options: [
                "Automated backups with 1-day retention",
                "Manual snapshots taken weekly",
                "AWS Backup with lifecycle policies",
                "Read replica promoted during restore"
            ],
            correct: 1,
            explanation: {
                correct: "Manual weekly snapshots have no ongoing cost beyond storage, sufficient for 4-hour RTO in dev environment.",
                whyWrong: {
                    0: "Automated backups incur backup storage charges continuously",
                    2: "AWS Backup adds service costs for dev environment",
                    3: "Read replicas double compute costs unnecessarily"
                },
                examStrategy: "Dev/test environments: manual snapshots. Production: automated backups. Read replicas for HA, not just backups."
            }
        },
        {
            id: 'cost_014',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to reduce data transfer costs between EC2 instances in different Availability Zones.",
            question: "Which approach minimizes inter-AZ data transfer costs?",
            options: [
                "Place all instances in the same AZ",
                "Use VPC endpoints for communication",
                "Enable VPC peering between AZs",
                "Implement data compression before transfer"
            ],
            correct: 0,
            explanation: {
                correct: "Same-AZ communication has no data transfer charges, eliminating inter-AZ transfer costs entirely.",
                whyWrong: {
                    1: "VPC endpoints are for AWS services, not EC2-to-EC2",
                    2: "VPC peering doesn't reduce inter-AZ charges",
                    3: "Compression reduces volume but charges still apply"
                },
                examStrategy: "Same-AZ = no transfer cost. Cross-AZ = $0.01/GB. Cross-region = higher costs. Design for data locality."
            }
        },
        {
            id: 'cost_015',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A media company processes video files using EC2 instances. Processing is fault-tolerant and can be interrupted. Jobs run 24/7 with varying load.",
            question: "Which instance strategy provides the BEST cost optimization?",
            options: [
                "Spot Fleet with diversified instance types and On-Demand base capacity",
                "Reserved Instances for baseline, On-Demand for peaks",
                "All Spot Instances with automatic replacement",
                "Savings Plans with On-Demand supplement"
            ],
            correct: 0,
            explanation: {
                correct: "Spot Fleet with diversification reduces interruption impact, On-Demand base ensures minimum capacity, providing 70-90% savings.",
                whyWrong: {
                    1: "Reserved Instances less flexible and more expensive than Spot for fault-tolerant work",
                    2: "All Spot risks complete capacity loss during shortages",
                    3: "Savings Plans more expensive than Spot for interruptible workloads"
                },
                examStrategy: "Spot for fault-tolerant batch processing. Mix Spot with On-Demand for reliability. Diversify instance types for availability."
            }
        },
        {
            id: 'cost_016',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company has unpredictable Lambda usage varying from 100 to 10,000 concurrent executions. They want to optimize costs while maintaining performance.",
            question: "Which Lambda configuration provides optimal cost-performance balance?",
            options: [
                "On-demand Lambda with auto-scaling",
                "Provisioned concurrency for baseline, on-demand for spikes",
                "All provisioned concurrency with maximum expected load",
                "Lambda@Edge for geographic distribution"
            ],
            correct: 1,
            explanation: {
                correct: "Provisioned concurrency for predictable baseline eliminates cold starts while on-demand handles spikes cost-effectively.",
                whyWrong: {
                    0: "Pure on-demand has cold start penalties during scaling",
                    2: "All provisioned for max load wastes money during low usage",
                    3: "Lambda@Edge is for CDN integration, not concurrency optimization"
                },
                examStrategy: "Provisioned concurrency for predictable load. On-demand for variable. Know the cost difference: provisioned is ~3x more expensive when running."
            }
        },
        {
            id: 'cost_017',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to archive 100TB of compliance data for 7 years with retrieval requirements of 48 hours for audits.",
            question: "Which storage solution provides the LOWEST total cost for this requirement?",
            options: [
                "S3 Glacier Deep Archive",
                "S3 Glacier Flexible Retrieval",
                "S3 Standard-IA with lifecycle transitions",
                "EBS snapshots archived to S3"
            ],
            correct: 0,
            explanation: {
                correct: "Glacier Deep Archive offers lowest storage cost ($0.00099/GB/month) with 48-hour retrieval meeting audit requirements.",
                whyWrong: {
                    1: "Glacier Flexible costs ~4x more than Deep Archive",
                    2: "Standard-IA costs ~12x more than Deep Archive",
                    3: "EBS snapshots more expensive and complex for pure archival"
                },
                examStrategy: "Deep Archive for long-term storage with rare access. 48-hour retrieval window = Deep Archive. 12-hour = Flexible Retrieval."
            }
        },
        {
            id: 'cost_018',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company runs identical production and staging environments. Staging is only used for pre-release testing (20 hours/month).",
            question: "How can staging environment costs be minimized?",
            options: [
                "Use AWS CloudFormation to create/delete staging on demand",
                "Purchase Reserved Instances for staging",
                "Run staging in a different region for lower costs",
                "Use smaller instance types in staging"
            ],
            correct: 0,
            explanation: {
                correct: "CloudFormation enables creating staging only when needed (20 hours/month), saving ~97% versus always-on.",
                whyWrong: {
                    1: "RIs charge for 24/7 usage, wasteful for 20 hours/month",
                    2: "Regional price differences are minimal, complexity not worth it",
                    3: "Smaller instances may not properly test production scenarios"
                },
                examStrategy: "Automate environment creation/deletion for temporary use. Infrastructure as Code enables cost optimization through automation."
            }
        },
        {
            id: 'cost_019',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company's monthly AWS bill shows $50,000 in data transfer charges, primarily from EC2 to S3 and between EC2 instances.",
            question: "Which solution would MOST reduce data transfer costs?",
            options: [
                "Implement VPC endpoints for S3 and consolidate EC2 instances in one AZ",
                "Use CloudFront for all data transfers",
                "Enable S3 Transfer Acceleration",
                "Implement AWS Direct Connect"
            ],
            correct: 0,
            explanation: {
                correct: "VPC endpoints eliminate S3 transfer charges, same-AZ consolidation eliminates inter-AZ transfer costs.",
                whyWrong: {
                    1: "CloudFront adds costs for origin fetches",
                    2: "Transfer Acceleration increases costs, not reduces",
                    3: "Direct Connect has high fixed costs, doesn't eliminate S3 charges"
                },
                examStrategy: "VPC endpoints = free S3 transfer. Same-AZ = free EC2-to-EC2. Know what transfers are free vs charged."
            }
        },
        {
            id: 'cost_020',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A SaaS company has 1000 customers with isolated databases. Most customers use < 1GB storage and have sporadic access patterns.",
            question: "Which database strategy minimizes costs while maintaining isolation?",
            options: [
                "Aurora Serverless v2 with database-per-customer",
                "DynamoDB with tenant partitioning",
                "RDS MySQL with schema-per-customer",
                "Individual RDS instances per customer"
            ],
            correct: 1,
            explanation: {
                correct: "DynamoDB with partition keys for tenant isolation provides pay-per-use pricing ideal for small, sporadic workloads.",
                whyWrong: {
                    0: "Aurora Serverless still has minimum capacity costs per database",
                    2: "RDS has minimum instance costs regardless of usage",
                    3: "1000 RDS instances extremely expensive for small databases"
                },
                examStrategy: "Multi-tenant: DynamoDB for variable loads, RDS with schemas for predictable loads. Avoid per-customer infrastructure for small tenants."
            }
        },
        {
            id: 'cost_021',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company processes daily reports using EMR clusters. Processing takes 3 hours and must complete by 6 AM each day.",
            question: "Which EMR configuration provides the LOWEST cost for this workload?",
            options: [
                "EMR on Spot Instances with automatic termination after job completion",
                "EMR on Reserved Instances running 24/7",
                "EMR Serverless with job-based scaling",
                "EMR on Savings Plans with scheduled scaling"
            ],
            correct: 0,
            explanation: {
                correct: "Spot Instances provide up to 90% savings, automatic termination ensures paying only for 3 hours daily processing.",
                whyWrong: {
                    1: "Reserved Instances charging 24/7 for 3-hour daily job is wasteful",
                    2: "EMR Serverless has higher per-unit costs than Spot",
                    3: "Savings Plans still charge for commitment, not usage-based"
                },
                examStrategy: "Transient EMR clusters on Spot for batch jobs. Persistent clusters only for streaming/continuous processing."
            }
        },
        {
            id: 'cost_022',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "easy",
            timeRecommendation: 90,
            scenario: "A company wants to identify unused resources and cost optimization opportunities across their AWS accounts.",
            question: "Which AWS service provides cost optimization recommendations?",
            options: [
                "AWS Trusted Advisor",
                "AWS Cost Explorer",
                "AWS Budgets",
                "AWS CloudTrail"
            ],
            correct: 0,
            explanation: {
                correct: "Trusted Advisor specifically provides cost optimization recommendations including unused resources and idle instances.",
                whyWrong: {
                    1: "Cost Explorer shows spending trends but limited recommendations",
                    2: "Budgets provides alerts, not optimization recommendations",
                    3: "CloudTrail is for API logging, not cost analysis"
                },
                examStrategy: "Trusted Advisor = recommendations. Cost Explorer = analysis. Compute Optimizer = right-sizing. Know which tool for which purpose."
            }
        },
        {
            id: 'cost_023',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to run Windows Server licenses on AWS. They already own licenses with Software Assurance from Microsoft.",
            question: "Which option provides the LOWEST cost for running Windows instances?",
            options: [
                "EC2 Dedicated Hosts with bring-your-own-license (BYOL)",
                "EC2 On-Demand instances with license included",
                "EC2 Savings Plans with Windows licensing",
                "RDS for SQL Server with license included"
            ],
            correct: 0,
            explanation: {
                correct: "Dedicated Hosts allow BYOL for Windows Server with Software Assurance, eliminating AWS license charges.",
                whyWrong: {
                    1: "License-included instances charge for Windows licensing you already own",
                    2: "Savings Plans don't eliminate Windows license charges",
                    3: "Question asks about Windows Server, not SQL Server"
                },
                examStrategy: "BYOL on Dedicated Hosts for existing enterprise licenses. Software Assurance enables License Mobility. Dedicated Hosts required for Windows BYOL."
            }
        },
        {
            id: 'cost_024',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "hard",
            timeRecommendation: 150,
            scenario: "A company runs containerized microservices with highly variable CPU usage (5-95%). Memory usage is consistent at 2GB per container.",
            question: "Which compute platform provides the MOST cost-effective container hosting?",
            options: [
                "ECS on EC2 with Spot Fleet and memory-optimized task placement",
                "ECS on Fargate with right-sized task definitions",
                "EKS with mixed On-Demand and Spot node groups",
                "Lambda with container image support"
            ],
            correct: 0,
            explanation: {
                correct: "ECS on EC2 Spot allows bin-packing multiple containers per instance and leverages Spot savings, optimal for memory-bound workloads.",
                whyWrong: {
                    1: "Fargate charges per task, expensive for memory-heavy, CPU-light workloads",
                    2: "EKS adds management overhead and Kubernetes complexity",
                    3: "Lambda has 10GB memory limit and duration-based pricing unsuitable for long-running containers"
                },
                examStrategy: "ECS on EC2 for bin-packing efficiency. Fargate for simplicity. Consider CPU vs memory utilization patterns for platform choice."
            }
        },
        {
            id: 'cost_025',
            domain: "Domain 4: Design Cost-Optimized Architectures",
            difficulty: "medium",
            timeRecommendation: 120,
            scenario: "A company needs to optimize costs for their data lake storing 500TB of data with varying access patterns across different datasets.",
            question: "Which S3 feature automatically optimizes storage costs based on access patterns?",
            options: [
                "S3 Intelligent-Tiering",
                "S3 Lifecycle policies",
                "S3 Storage Class Analysis",
                "S3 Inventory reports"
            ],
            correct: 0,
            explanation: {
                correct: "Intelligent-Tiering automatically moves objects between access tiers based on changing access patterns without retrieval fees.",
                whyWrong: {
                    1: "Lifecycle policies require manual configuration and don't adapt to changing patterns",
                    2: "Storage Class Analysis provides recommendations but doesn't automatically optimize",
                    3: "Inventory reports provide data but no automatic optimization"
                },
                examStrategy: "Intelligent-Tiering for unknown/changing access patterns. Lifecycle policies for predictable patterns. Automation vs manual configuration."
            }
        },
     
 {
        id: 'cost_026',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs 100 EC2 instances across development, staging, and production. They want to reduce costs without impacting production performance.",
        question: "Which strategy provides the BEST cost optimization across environments?",
        options: [
            "Reserved Instances for production, Spot for dev/staging, Instance Scheduler for non-prod",
            "Savings Plans for all environments equally",
            "All On-Demand with auto-scaling to minimize waste",
            "All Spot Instances with fallback to On-Demand"
        ],
        correct: 0,
        explanation: {
            correct: "RIs provide predictable savings for stable production, Spot maximizes savings for non-critical environments, scheduling eliminates waste.",
            whyWrong: {
                1: "Savings Plans charge for dev/staging even when stopped",
                2: "On-Demand is most expensive option",
                3: "Spot for production risks availability"
            },
            examStrategy: "Match pricing model to workload criticality. Production = Reserved/Savings Plans. Dev = Spot/Scheduled. Layer strategies."
        }
    },
    {
        id: 'cost_027',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company stores 500TB of data across S3, with 20% accessed daily, 30% monthly, and 50% rarely accessed but needed for compliance.",
        question: "Which S3 storage strategy minimizes cost while meeting access requirements?",
        options: [
            "20% in Standard, 30% in Standard-IA, 50% in Glacier Deep Archive",
            "All data in Intelligent-Tiering",
            "All data in Standard with lifecycle to Glacier after 90 days",
            "50% in One Zone-IA, 50% in Glacier"
        ],
        correct: 0,
        explanation: {
            correct: "Matching storage classes to access patterns optimizes costs: Standard for frequent, IA for occasional, Deep Archive for rare compliance.",
            whyWrong: {
                1: "Intelligent-Tiering monitoring fees add up for 500TB",
                2: "Keeping rarely accessed data in Standard for 90 days wastes money",
                3: "One Zone-IA risks data loss for compliance data"
            },
            examStrategy: "Match storage class to access pattern. Deep Archive for compliance. Avoid Intelligent-Tiering fees at large scale."
        }
    },
    {
        id: 'cost_028',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A startup with unpredictable growth wants to minimize AWS costs while maintaining flexibility to scale.",
        question: "Which purchasing strategy provides the BEST balance of cost savings and flexibility?",
        options: [
            "Compute Savings Plans with 1-year term",
            "3-year All Upfront Reserved Instances",
            "On-Demand only with aggressive auto-scaling",
            "Spot Instances for all workloads"
        ],
        correct: 0,
        explanation: {
            correct: "1-year Compute Savings Plans provide ~30% savings with flexibility to change instance types and regions as the startup grows.",
            whyWrong: {
                1: "3-year RIs lock in specific instances, risky for unpredictable growth",
                2: "On-Demand provides flexibility but no cost savings",
                3: "Spot isn't suitable for all workloads"
            },
            examStrategy: "Shorter terms for uncertainty. Savings Plans for flexibility. Compute Plans work across EC2, Lambda, Fargate."
        }
    },
    {
        id: 'cost_029',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company noticed their AWS bill includes charges for unattached EBS volumes and unused Elastic IPs.",
        question: "Which tool helps identify and eliminate these unused resources?",
        options: [
            "AWS Trusted Advisor with Cost Optimization checks",
            "AWS Cost Explorer with forecasting",
            "AWS Budgets with alerts",
            "CloudWatch billing alarms"
        ],
        correct: 0,
        explanation: {
            correct: "Trusted Advisor specifically identifies unused resources like unattached EBS volumes and idle Elastic IPs.",
            whyWrong: {
                1: "Cost Explorer shows spending trends but doesn't identify specific unused resources",
                2: "Budgets alert on spending but don't identify waste",
                3: "Billing alarms notify about costs but don't find unused resources"
            },
            examStrategy: "Trusted Advisor for waste identification. Cost Explorer for analysis. Budgets for alerts. Regular cleanup saves money."
        }
    },
    {
        id: 'cost_030',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A media company processes video files using GPU instances for 4 hours each night. The processing can tolerate interruptions.",
        question: "Which instance strategy provides the LOWEST cost for GPU processing?",
        options: [
            "Spot Instances with persistent request and checkpoint/resume logic",
            "Reserved GPU instances running 24/7",
            "On-Demand GPU instances with Instance Scheduler",
            "Lambda functions with container images"
        ],
        correct: 0,
        explanation: {
            correct: "Spot GPU instances provide up to 90% discount, checkpoint/resume handles interruptions for batch processing.",
            whyWrong: {
                1: "Reserved 24/7 charges for unused 20 hours daily",
                2: "On-Demand GPU instances are extremely expensive",
                3: "Lambda doesn't support GPU acceleration"
            },
            examStrategy: "Spot for GPU batch processing. Checkpoint/resume for interruption handling. GPU instances are expensive - optimize usage."
        }
    },
    {
        id: 'cost_031',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A SaaS company has 5000 small customer databases (< 100MB each) with sporadic access patterns. Most are idle 95% of the time.",
        question: "Which database architecture minimizes costs for many small, idle databases?",
        options: [
            "Single Aurora Serverless v2 cluster with schema-per-customer",
            "Individual RDS instances per customer",
            "DynamoDB with tenant partitioning",
            "Aurora provisioned with read replicas"
        ],
        correct: 0,
        explanation: {
            correct: "Aurora Serverless v2 scales to zero for idle periods, schema separation maintains isolation at fraction of per-instance cost.",
            whyWrong: {
                1: "5000 RDS instances would be extremely expensive",
                2: "DynamoDB charges for storage even when idle",
                3: "Provisioned Aurora charges continuously regardless of usage"
            },
            examStrategy: "Serverless for sporadic workloads. Multi-tenancy reduces costs. Aurora Serverless v2 scales to zero."
        }
    },
    {
        id: 'cost_032',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company wants to reduce their NAT Gateway charges of $5,000/month for data processing workloads.",
        question: "Which architecture change MOST reduces NAT Gateway costs?",
        options: [
            "Use NAT Instances on smaller EC2 instances instead",
            "Move workloads to public subnets with security groups",
            "VPC endpoints for S3 and DynamoDB access",
            "Reduce the number of availability zones"
        ],
        correct: 2,
        explanation: {
            correct: "VPC endpoints route traffic privately to AWS services, bypassing NAT Gateway and eliminating data processing charges.",
            whyWrong: {
                0: "NAT Instances require management and may not handle the load",
                1: "Public subnets compromise security architecture",
                3: "Reducing AZs impacts availability"
            },
            examStrategy: "VPC endpoints eliminate NAT charges for AWS services. Gateway endpoints (S3, DynamoDB) are free. Significant savings for data-heavy workloads."
        }
    },
    {
        id: 'cost_033',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company has been paying for Premium Support but rarely uses it. They want to reduce support costs.",
        question: "What should be evaluated FIRST before changing support plans?",
        options: [
            "Review support case history and compliance requirements",
            "Immediately downgrade to Basic support",
            "Switch to Developer support",
            "Cancel all AWS support"
        ],
        correct: 0,
        explanation: {
            correct: "Review actual usage and requirements ensures the company maintains necessary support levels while optimizing costs.",
            whyWrong: {
                1: "Immediate downgrade might violate compliance or leave critical issues unsupported",
                2: "Developer support not suitable for production",
                3: "Basic support might be required for compliance"
            },
            examStrategy: "Evaluate before changing. Consider compliance requirements. Business/Enterprise support often required for production."
        }
    },
    {
        id: 'cost_034',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs Lambda functions processing 10 billion requests monthly. Functions average 200ms duration with 512MB memory.",
        question: "Which optimization provides the GREATEST cost reduction for Lambda?",
        options: [
            "Reduce memory to 256MB if performance remains acceptable",
            "Increase memory to 3GB to reduce duration",
            "Convert to EC2 with auto-scaling",
            "Purchase Compute Savings Plans"
        ],
        correct: 0,
        explanation: {
            correct: "Halving memory allocation halves cost per invocation; if duration remains similar, this provides ~50% cost reduction.",
            whyWrong: {
                1: "Increasing memory might reduce duration but increases cost per 100ms",
                2: "EC2 requires management and might not be cost-effective",
                3: "Savings Plans provide ~17% discount, less than memory optimization"
            },
            examStrategy: "Lambda pricing: memory × duration. Optimize both. Test different memory configurations. Savings Plans apply to Lambda."
        }
    },
    {
        id: 'cost_035',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company needs to archive 10PB of data for 10 years. Data might be needed for legal discovery with 24-hour retrieval requirement.",
        question: "Which storage solution provides the LOWEST total cost over 10 years?",
        options: [
            "S3 Glacier Deep Archive with bulk retrieval",
            "S3 Glacier Flexible Retrieval",
            "S3 Intelligent-Tiering Archive",
            "AWS Snowball devices stored on-premises"
        ],
        correct: 0,
        explanation: {
            correct: "Deep Archive at $0.00099/GB/month is lowest cost, bulk retrieval (12-48 hours) meets 24-hour requirement.",
            whyWrong: {
                1: "Flexible Retrieval costs 4x more than Deep Archive",
                2: "Intelligent-Tiering has monitoring fees that add up for 10PB",
                3: "On-premises storage has hardware, power, and maintenance costs"
            },
            examStrategy: "Deep Archive for long-term storage. Bulk retrieval for cost optimization. 10PB × 10 years = consider every cent/GB."
        }
    },
    {
        id: 'cost_036',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs identical disaster recovery infrastructure that's only used during quarterly DR tests.",
        question: "How can DR infrastructure costs be minimized while maintaining readiness?",
        options: [
            "Use AWS Backup to restore infrastructure only during tests",
            "Maintain pilot light with automation to scale up",
            "Keep full warm standby running continuously",
            "Manual recreation during DR events"
        ],
        correct: 1,
        explanation: {
            correct: "Pilot light keeps minimal core components running with automation to quickly provision full infrastructure when needed.",
            whyWrong: {
                0: "Backup restoration might take too long for DR requirements",
                2: "Warm standby running continuously is expensive for quarterly use",
                3: "Manual recreation is slow and error-prone"
            },
            examStrategy: "Pilot light balances cost and recovery time. Automation ensures quick scaling. Test regularly but minimize standing costs."
        }
    },
    {
        id: 'cost_037',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company's RDS database has Read Replicas that are rarely used, costing $2000/month.",
        question: "What should be done with underutilized Read Replicas?",
        options: [
            "Delete unused replicas and create them on-demand when needed",
            "Keep them for disaster recovery",
            "Convert them to smaller instance types",
            "Move them to different regions"
        ],
        correct: 0,
        explanation: {
            correct: "Deleting unused replicas saves immediate costs; they can be recreated when actually needed.",
            whyWrong: {
                1: "Automated backups and Multi-AZ provide DR, not read replicas",
                2: "Smaller instances still cost money if unused",
                3: "Different regions don't reduce costs for unused resources"
            },
            examStrategy: "Delete unused resources. Read replicas for read scaling, not DR. Can recreate from snapshots when needed."
        }
    },
    {
        id: 'cost_038',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company processes 1TB of logs daily through CloudWatch Logs, with $30,000 monthly ingestion costs.",
        question: "Which alternative provides the MOST cost-effective log processing?",
        options: [
            "Stream directly to S3 with Kinesis Data Firehose, query with Athena",
            "Keep all logs in CloudWatch with shorter retention",
            "Use CloudWatch Logs Insights for everything",
            "Export to S3 daily with lifecycle policies"
        ],
        correct: 0,
        explanation: {
            correct: "Kinesis Firehose to S3 costs ~$35/TB vs CloudWatch Logs ~$500/TB ingestion, Athena queries cost-effectively.",
            whyWrong: {
                1: "Shorter retention doesn't reduce ingestion costs",
                2: "Logs Insights adds query costs on top of ingestion",
                3: "Export doesn't eliminate CloudWatch ingestion costs"
            },
            examStrategy: "CloudWatch Logs expensive at scale. S3 + Athena for cost-effective log analytics. Kinesis Firehose for streaming to S3."
        }
    },
    {
        id: 'cost_039',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A global company has data transfer costs of $100,000/month between regions for application synchronization.",
        question: "Which architecture change MOST reduces inter-region transfer costs?",
        options: [
            "Implement event-driven architecture with regional processing",
            "Use AWS Global Accelerator",
            "Increase Direct Connect bandwidth",
            "Compress all data before transfer"
        ],
        correct: 0,
        explanation: {
            correct: "Event-driven architecture processes data locally in each region, only syncing minimal event data instead of full replication.",
            whyWrong: {
                1: "Global Accelerator doesn't reduce transfer costs",
                2: "Direct Connect doesn't eliminate inter-region charges",
                3: "Compression helps but doesn't address architectural inefficiency"
            },
            examStrategy: "Minimize inter-region transfer through architecture. Process locally, sync globally. Events over data replication."
        }
    },
    {
        id: 'cost_040',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs batch jobs on m5.24xlarge instances ($4.60/hour) for 2 hours daily. Jobs are time-flexible.",
        question: "Which alternative provides the MOST cost savings?",
        options: [
            "Spot Instances with flexible start times to get best prices",
            "Smaller instances running for longer duration",
            "Reserved Instances with All Upfront payment",
            "Lambda functions to eliminate servers"
        ],
        correct: 0,
        explanation: {
            correct: "Spot instances provide up to 90% discount ($0.46/hour), flexible timing allows waiting for optimal prices.",
            whyWrong: {
                1: "Smaller instances might not complete work in time",
                2: "RIs charge 24/7 for 2-hour daily usage",
                3: "Lambda timeout and memory limits unsuitable for batch"
            },
            examStrategy: "Spot for flexible batch jobs. Time flexibility = better Spot prices. Large instances often have better Spot discounts."
        }
    },
    {
        id: 'cost_041',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to reduce costs for their proof-of-concept projects that run for 1-2 weeks.",
        question: "Which pricing model is MOST cost-effective for short-term POC projects?",
        options: [
            "On-Demand instances with immediate termination after POC",
            "1-year Reserved Instances",
            "3-year Savings Plans",
            "Dedicated Hosts"
        ],
        correct: 0,
        explanation: {
            correct: "On-Demand provides flexibility to start/stop immediately without commitments, ideal for short-term POCs.",
            whyWrong: {
                1: "1-year commitment wastes money for 2-week projects",
                2: "3-year commitment extremely wasteful for POCs",
                3: "Dedicated Hosts are most expensive option"
            },
            examStrategy: "On-Demand for short-term. No commitments for POCs. Terminate immediately after use."
        }
    },
    {
        id: 'cost_042',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company has 50TB of infrequently accessed data in S3 Standard costing $1,150/month.",
        question: "Which storage class would provide the MOST savings for data accessed once per quarter?",
        options: [
            "S3 Glacier Instant Retrieval (~$200/month)",
            "S3 Standard-IA (~$640/month)",
            "S3 One Zone-IA (~$512/month)",
            "S3 Intelligent-Tiering"
        ],
        correct: 0,
        explanation: {
            correct: "Glacier Instant Retrieval provides 82% savings for rarely accessed data with millisecond retrieval when needed.",
            whyWrong: {
                1: "Standard-IA costs 3x more than Glacier Instant",
                2: "One Zone-IA risks data loss and still costs more",
                3: "Intelligent-Tiering adds monitoring fees for 50TB"
            },
            examStrategy: "Glacier Instant for rare access with fast retrieval. Quarterly access = rare. Calculate savings percentages."
        }
    },
    {
        id: 'cost_043',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company runs 1000 containers across ECS with variable CPU (5-80%) but consistent memory usage.",
        question: "Which compute strategy minimizes costs for this container workload?",
        options: [
            "ECS on EC2 with Spot fleet and memory-optimized instance types",
            "Fargate with right-sized task definitions",
            "EKS with auto-scaling node groups",
            "Lambda with container images"
        ],
        correct: 0,
        explanation: {
            correct: "ECS on EC2 allows bin packing containers to maximize memory utilization, Spot reduces costs by up to 90%.",
            whyWrong: {
                1: "Fargate charges per task, expensive for memory-heavy workloads",
                2: "EKS adds management overhead and cluster costs",
                3: "Lambda has 10GB limit and duration pricing unsuitable"
            },
            examStrategy: "ECS on EC2 for bin packing efficiency. Spot for container workloads. Fargate for simplicity over cost."
        }
    },
    {
        id: 'cost_044',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company pays $10,000/month for Application Load Balancers across 20 microservices with light traffic.",
        question: "How can ALB costs be reduced for multiple microservices?",
        options: [
            "Use single ALB with host-based routing to multiple target groups",
            "Replace with Network Load Balancers",
            "Use Classic Load Balancers instead",
            "Implement API Gateway for all services"
        ],
        correct: 0,
        explanation: {
            correct: "Single ALB can route to multiple services using host headers or paths, reducing from 20 ALBs to 1.",
            whyWrong: {
                1: "NLB costs similar to ALB",
                2: "Classic LB is legacy and doesn't support modern features",
                3: "API Gateway has request-based pricing that might cost more"
            },
            examStrategy: "Consolidate ALBs using routing rules. Host-based and path-based routing. One ALB can serve many services."
        }
    },
    {
        id: 'cost_045',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A development team forgot to terminate EC2 instances from a completed project, resulting in $5,000 of unnecessary charges.",
        question: "What prevents forgotten resources from accumulating costs?",
        options: [
            "Implement tagging and automated termination policies",
            "Larger approval process for creating resources",
            "Only use production accounts",
            "Limit instance types developers can use"
        ],
        correct: 0,
        explanation: {
            correct: "Tagging identifies resource ownership and purpose, automation can terminate resources based on tags and age.",
            whyWrong: {
                1: "Approval processes slow development without preventing waste",
                2: "Production accounts don't prevent forgotten resources",
                3: "Instance type limits don't prevent forgetting to terminate"
            },
            examStrategy: "Tag everything. Automate cleanup. Use AWS Config for compliance. Cost allocation tags for accountability."
        }
    },
    {
        id: 'cost_046',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs Windows workloads on AWS and spends $50,000/month on Windows licenses.",
        question: "Which option could significantly reduce Windows licensing costs?",
        options: [
            "Bring Your Own License (BYOL) on Dedicated Hosts",
            "Switch to Linux alternatives where possible",
            "Use Spot Instances for Windows workloads",
            "Purchase Reserved Instances with Windows"
        ],
        correct: 1,
        explanation: {
            correct: "Linux alternatives eliminate Windows licensing costs entirely, providing the most significant savings.",
            whyWrong: {
                0: "BYOL requires existing licenses and Dedicated Hosts",
                2: "Spot doesn't reduce Windows license costs",
                3: "RIs with Windows still include license costs"
            },
            examStrategy: "Consider Linux alternatives first. BYOL if you have licenses. Windows licensing adds significant cost."
        }
    },
    {
        id: 'cost_047',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A data lake ingests 100TB monthly with 1% accessed frequently, 9% occasionally, and 90% rarely but needed for compliance.",
        question: "Which tiered storage approach minimizes costs while maintaining accessibility?",
        options: [
            "S3 Intelligent-Tiering with Archive Access tiers enabled",
            "Manual lifecycle policies to different storage classes",
            "All data in Glacier with S3 cache layer",
            "Separate S3 buckets for each access tier"
        ],
        correct: 1,
        explanation: {
            correct: "Manual lifecycle policies avoid Intelligent-Tiering monitoring fees on 100TB while optimizing storage costs.",
            whyWrong: {
                0: "Intelligent-Tiering monitoring costs $2,500/month for 100TB",
                2: "Glacier retrieval costs and delays impact accessibility",
                3: "Separate buckets complicate data management"
            },
            examStrategy: "Lifecycle policies for predictable patterns. Intelligent-Tiering for unpredictable. Consider monitoring costs at scale."
        }
    },
    {
        id: 'cost_048',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company's monthly data transfer costs are: $3,000 to internet, $2,000 between AZs, and $1,000 between regions.",
        question: "Which optimization provides the GREATEST cost reduction?",
        options: [
            "Implement CloudFront to reduce internet egress",
            "Consolidate resources in single AZ",
            "Eliminate cross-region transfers",
            "Compress all data transfers"
        ],
        correct: 0,
        explanation: {
            correct: "CloudFront egress costs less than direct internet egress from EC2/S3, potentially saving 50% on the largest cost component.",
            whyWrong: {
                1: "Single AZ compromises availability for $2,000 savings",
                2: "Cross-region might be required for DR/compliance",
                3: "Compression helps but doesn't address pricing differences"
            },
            examStrategy: "CloudFront reduces egress costs. Balance cost optimization with availability. Target largest cost components first."
        }
    },
    {
        id: 'cost_049',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A company wants to track and control AWS spending by department.",
        question: "What is the BEST way to track departmental AWS costs?",
        options: [
            "Use cost allocation tags and Cost Explorer filtering",
            "Create separate AWS accounts per department",
            "Manual spreadsheet tracking",
            "CloudWatch billing metrics"
        ],
        correct: 0,
        explanation: {
            correct: "Cost allocation tags allow granular cost tracking within accounts, Cost Explorer provides filtering and reporting by tags.",
            whyWrong: {
                1: "Separate accounts add complexity",
                2: "Manual tracking is error-prone and doesn't scale",
                3: "CloudWatch metrics don't provide departmental breakdown"
            },
            examStrategy: "Cost allocation tags for tracking. Tag consistency is critical. Cost Explorer for analysis and reporting."
        }
    },
    {
        id: 'cost_050',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs a web application with highly variable traffic: 100 requests/second baseline, 10,000 requests/second during daily 1-hour peaks.",
        question: "Which architecture provides the MOST cost-effective scaling?",
        options: [
            "Auto Scaling with Reserved Instances for baseline, On-Demand for peaks",
            "All On-Demand with aggressive auto-scaling",
            "All Reserved Instances sized for peak",
            "Serverless with API Gateway and Lambda"
        ],
        correct: 0,
        explanation: {
            correct: "RIs for predictable baseline provides ~40% savings, On-Demand for peaks avoids over-provisioning for 23 hours daily.",
            whyWrong: {
                1: "All On-Demand misses savings on predictable baseline",
                2: "All RIs wastes money on unused peak capacity 95% of time",
                3: "Lambda might be more expensive at high sustained loads"
            },
            examStrategy: "Reserved for baseline, On-Demand for peaks. Mix purchasing options. Serverless for truly variable workloads."
        }
    },
{
        id: 'cost_051',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company has 500 EC2 instances running 24/7 with average CPU utilization of 15%. They want to reduce costs without impacting performance.",
        question: "Which strategy provides the GREATEST cost reduction?",
        options: [
            "Right-size instances based on CPU metrics and purchase Savings Plans for the new sizes",
            "Keep current sizes but purchase Reserved Instances",
            "Convert everything to Spot Instances",
            "Move to larger instances to reduce instance count"
        ],
        correct: 0,
        explanation: {
            correct: "Right-sizing eliminates waste from oversized instances, Savings Plans provide additional discounts on the optimized infrastructure.",
            whyWrong: {
                1: "RIs on oversized instances perpetuate waste",
                2: "Spot unsuitable for 24/7 production workloads",
                3: "Larger instances may increase costs without utilization improvement"
            },
            examStrategy: "Right-size first, then apply pricing discounts. Fix utilization before committing to reservations."
        }
    },
    {
        id: 'cost_052',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A media company spends $100K/month on S3 storage. Analysis shows: 10% accessed daily, 20% accessed weekly, 30% accessed monthly, 40% never accessed after 90 days.",
        question: "Which S3 lifecycle policy minimizes costs while maintaining appropriate access times?",
        options: [
            "Standard for 7 days → Standard-IA for 30 days → Glacier Instant for 90 days → Glacier Deep Archive after 180 days",
            "Keep everything in Standard for simplicity",
            "Move everything to Glacier immediately",
            "Use Intelligent-Tiering for everything"
        ],
        correct: 0,
        explanation: {
            correct: "This tiering matches access patterns: Standard for daily, Standard-IA for weekly/monthly, Glacier Instant for rare, Deep Archive for never.",
            whyWrong: {
                1: "Standard for all data wastes money on unaccessed data",
                2: "Immediate Glacier breaks frequently accessed data",
                3: "Intelligent-Tiering monitoring fees add up at this scale"
            },
            examStrategy: "Match storage class to access frequency. Consider retrieval times and costs. Deep Archive for true archival."
        }
    },
    {
        id: 'cost_053',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A SaaS company has predictable compute needs: 100 instances baseline, 150 instances during business hours, up to 300 during peaks.",
        question: "Which purchasing strategy minimizes costs for this usage pattern?",
        options: [
            "100 Reserved Instances, 50 Scheduled Reserved Instances, 150 Spot Instances",
            "300 On-Demand Instances with auto-scaling",
            "300 Reserved Instances to cover peaks",
            "All Spot Instances with overprovisioning"
        ],
        correct: 0,
        explanation: {
            correct: "RIs for baseline provides maximum discount, Scheduled RIs for predictable increases, Spot for variable peaks optimizes cost.",
            whyWrong: {
                1: "On-Demand most expensive option",
                2: "300 RIs wastes money on unused capacity",
                3: "All Spot risks availability for baseline needs"
            },
            examStrategy: "Layer purchasing: RI for baseline, Scheduled for predictable, Spot for peaks. Match commitment to usage pattern."
        }
    },
    {
        id: 'cost_054',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "easy",
        timeRecommendation: 90,
        scenario: "A startup is paying high costs for NAT Gateways processing 10TB of data transfer monthly to S3.",
        question: "How can NAT Gateway costs be eliminated for S3 transfers?",
        options: [
            "Use VPC Endpoints for S3 instead of NAT Gateway",
            "Replace NAT Gateway with NAT Instance",
            "Move S3 bucket to same region",
            "Enable S3 Transfer Acceleration"
        ],
        correct: 0,
        explanation: {
            correct: "VPC Endpoints provide private connectivity to S3 without NAT Gateway, eliminating data processing charges.",
            whyWrong: {
                1: "NAT Instance still has data processing costs",
                2: "Same region doesn't eliminate NAT charges",
                3: "Transfer Acceleration increases costs"
            },
            examStrategy: "VPC Endpoints eliminate NAT charges for AWS services. Gateway endpoints are free for S3 and DynamoDB."
        }
    },
    {
        id: 'cost_055',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "medium",
        timeRecommendation: 120,
        scenario: "A company runs 1000 identical web servers. They need high availability but want to minimize licensing costs for commercial software.",
        question: "Which strategy minimizes software licensing costs while maintaining availability?",
        options: [
            "Use Auto Scaling with minimum viable licenses and scale horizontally with demand",
            "License all 1000 servers for peak capacity",
            "Use open-source alternatives only",
            "Negotiate enterprise agreement for unlimited licenses"
        ],
        correct: 0,
        explanation: {
            correct: "Auto Scaling with minimum licenses dynamically adjusts capacity, paying only for licenses actually in use.",
            whyWrong: {
                1: "Licensing all servers wastes money on idle capacity",
                2: "Open-source may not meet requirements",
                3: "Unlimited licenses often more expensive than actual usage"
            },
            examStrategy: "License for actual use, not peak capacity. Auto Scaling reduces license requirements. Consider license-included AMIs."
        }
    },
    {
        id: 'cost_056',
        domain: "Domain 4: Design Cost-Optimized Architectures",
        difficulty: "hard",
        timeRecommendation: 150,
        scenario: "A company processes 100TB of logs daily. Current costs: $50K/month for processing, $30K/month for storage. Logs are queried frequently for 7 days, occasionally for 30 days, rarely after.",
        question: "Which architecture provides the LOWEST total cost for this logging system?",
        options: [
            "Kinesis Firehose → S3 Standard → Athena queries, lifecycle to Glacier after 30 days",
            "CloudWatch Logs with 7-day retention",
            "OpenSearch cluster with hot-warm-cold architecture",
            "EMR cluster processing to RDS"
        ],
        correct: 0, 
        explanation: {
        correct: "Firehose provides low-cost ingestion, S3 is cheapest for storage, Athena serverless eliminates cluster costs, Glacier for long-term.",
        whyWrong: {
            1: "CloudWatch Logs expensive at 100TB daily scale",
            2: "OpenSearch cluster costs high for 100TB daily",
            3: "EMR and RDS expensive for this volume"
        },
        examStrategy: "S3 + Athena for log analytics at scale. Serverless over clusters for variable workloads. Lifecycle policies for cost optimization."
    }
},
{
    id: 'cost_057',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company wants to reduce RDS costs. Their database has 5TB of data but only 500GB is actively queried.",
    question: "Which strategy provides the BEST cost optimization for this database?",
    options: [
        "Archive historical data to S3, use Federated Query when needed",
        "Add more read replicas for better performance",
        "Upgrade to larger instance with more memory",
        "Enable Multi-AZ for better availability"
    ],
    correct: 0,
    explanation: {
        correct: "Archiving cold data to S3 reduces RDS storage costs by 90%, Federated Query allows occasional access when needed.",
        whyWrong: {
            1: "Read replicas increase costs",
            2: "Larger instance increases costs",
            3: "Multi-AZ doubles storage costs"
        },
        examStrategy: "Separate hot and cold data. Archive to S3 for cost savings. Federated Query for occasional access to archived data."
    }
},
{
    id: 'cost_058',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company is paying for idle Elastic IPs not associated with running instances.",
    question: "What is the BEST way to avoid Elastic IP charges?",
    options: [
        "Release unassociated Elastic IPs immediately",
        "Associate them with stopped instances",
        "Move to IPv6 only",
        "Use more Elastic IPs to get volume discount"
    ],
    correct: 0,
    explanation: {
        correct: "Releasing unassociated Elastic IPs immediately stops the hourly charges for idle IPs.",
        whyWrong: {
            1: "Associated with stopped instances still incurs charges",
            2: "IPv6 may not be compatible with all systems",
            3: "No volume discount for Elastic IPs, more IPs mean more cost"
        },
        examStrategy: "Release unused Elastic IPs. Only keep IPs actually in use. Use DNS instead of hard-coded IPs when possible."
    }
},
{
    id: 'cost_059',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company runs batch processing jobs taking 4-6 hours nightly. Jobs can be interrupted and resumed. Currently using On-Demand instances costing $10K/month.",
    question: "Which strategy could reduce costs by up to 90%?",
    options: [
        "Spot Instances with checkpointing and automatic bidding strategies",
        "Reserved Instances for the batch processing",
        "Smaller instances running longer",
        "Lambda functions instead of EC2"
    ],
    correct: 0,
    explanation: {
        correct: "Spot Instances provide up to 90% discount, checkpointing handles interruptions, perfect for fault-tolerant batch jobs.",
        whyWrong: {
            1: "RIs provide only 30-70% discount and require 24/7 commitment",
            2: "Smaller instances still On-Demand pricing",
            3: "Lambda timeout (15 min) insufficient for 4-6 hour jobs"
        },
        examStrategy: "Spot for interruptible batch workloads. Checkpointing enables Spot usage. 90% savings possible with Spot."
    }
},
{
    id: 'cost_060',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A global company has data transfer costs of $200K/month: 40% cross-region replication, 30% CloudFront to origin, 30% EC2 cross-AZ.",
    question: "Which optimization provides the GREATEST cost reduction?",
    options: [
        "Reduce replication frequency, enable CloudFront caching, consolidate EC2 in single AZ where possible",
        "Move everything to one region",
        "Use Direct Connect for all transfers",
        "Compress all data before transfer"
    ],
    correct: 0,
    explanation: {
        correct: "Combined approach: less frequent replication reduces 40%, better caching reduces origin fetches by 80%, single AZ eliminates the 30%.",
        whyWrong: {
            1: "Single region eliminates global presence",
            2: "Direct Connect doesn't reduce AWS internal transfer costs",
            3: "Compression helps but doesn't address root causes"
        },
        examStrategy: "Attack largest cost drivers first. Reduce transfer frequency and volume. Consolidate when possible without sacrificing availability."
    }
},
{
    id: 'cost_061',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company's development team launches EC2 instances for testing but forgets to terminate them, resulting in $20K monthly waste.",
    question: "Which solution BEST prevents forgotten instances from accumulating costs?",
    options: [
        "AWS Lambda function triggered daily to terminate instances with 'dev' tag older than 7 days",
        "Email reminders to developers",
        "Larger instances so fewer are needed",
        "Manual weekly reviews"
    ],
    correct: 0,
    explanation: {
        correct: "Automated termination based on tags and age ensures forgotten instances are cleaned up without human intervention.",
        whyWrong: {
            1: "Email reminders often ignored",
            2: "Larger instances don't solve the forgetting problem",
            3: "Manual reviews prone to human error"
        },
        examStrategy: "Automate cost controls. Tag-based automation for environment management. Set automatic termination for non-production."
    }
},
{
    id: 'cost_062',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company wants to identify unused EBS volumes that are still incurring charges.",
    question: "Which tool helps identify unattached EBS volumes?",
    options: [
        "AWS Cost Explorer with EBS filter",
        "CloudWatch metrics",
        "VPC Flow Logs",
        "CloudTrail logs"
    ],
    correct: 0,
    explanation: {
        correct: "Cost Explorer can filter and identify EBS volumes that are unattached but still incurring charges.",
        whyWrong: {
            1: "CloudWatch shows performance, not attachment status",
            2: "Flow Logs track network traffic, not EBS",
            3: "CloudTrail shows API calls, not current state"
        },
        examStrategy: "Cost Explorer for cost analysis and waste identification. Regular reviews of unattached resources. Trusted Advisor also helps."
    }
},
{
    id: 'cost_063',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A video streaming company needs to reduce CloudFront costs currently at $100K/month for global content delivery.",
    question: "Which optimization strategy reduces CloudFront costs while maintaining performance?",
    options: [
        "Increase cache TTLs, implement Origin Shield, and use CloudFront compression",
        "Remove CloudFront and serve directly from S3",
        "Use multiple smaller distributions",
        "Switch to a different CDN provider"
    ],
    correct: 0,
    explanation: {
        correct: "Longer TTLs reduce origin fetches, Origin Shield reduces origin load by 90%, compression reduces data transfer costs.",
        whyWrong: {
            1: "Direct S3 serving impacts global performance",
            2: "Multiple distributions increase complexity without cost benefit",
            3: "CloudFront typically most cost-effective with AWS integration"
        },
        examStrategy: "Optimize cache hit ratio first. Origin Shield for additional caching layer. Compression reduces transfer volume."
    }
},
{
    id: 'cost_064',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company runs 200 Windows Server instances 24/7. They own 200 Windows licenses with Software Assurance. Currently paying for Windows in AWS.",
    question: "How can they eliminate Windows licensing charges in AWS?",
    options: [
        "Migrate to Dedicated Hosts with bring-your-own-license (BYOL)",
        "Switch to Linux instances",
        "Purchase AWS Windows licenses in bulk",
        "Use Savings Plans for Windows instances"
    ],
    correct: 0,
    explanation: {
        correct: "Dedicated Hosts allow BYOL for Windows with Software Assurance, eliminating per-instance Windows charges from AWS.",
        whyWrong: {
            1: "Linux migration may not be feasible for Windows applications",
            2: "AWS doesn't offer bulk Windows licenses",
            3: "Savings Plans reduce but don't eliminate Windows charges"
        },
        examStrategy: "BYOL on Dedicated Hosts for existing licenses. Software Assurance enables license mobility. Significant savings for large deployments."
    }
},
{
    id: 'cost_065',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company uses AWS Lambda for their entire application, resulting in $50K/month bills. Analysis shows 80% of cost from high-frequency, long-duration functions.",
    question: "Which optimization provides the GREATEST cost reduction?",
    options: [
        "Move high-frequency, long-duration functions to ECS with Fargate Spot",
        "Increase Lambda memory to reduce duration",
        "Use Reserved Capacity for Lambda",
        "Rewrite functions in a faster language"
    ],
    correct: 0,
    explanation: {
        correct: "Lambda is expensive for sustained workloads; Fargate Spot provides up to 70% savings for long-running, high-frequency tasks.",
        whyWrong: {
            1: "More memory might not reduce duration enough to offset cost",
            2: "Lambda doesn't have reserved capacity pricing",
            3: "Language change provides marginal improvement"
        },
        examStrategy: "Lambda for sporadic, short tasks. Containers for sustained workloads. Identify break-even point between Lambda and containers."
    }
},
{
    id: 'cost_066',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company wants to reduce their AWS bill but doesn't know where to start.",
    question: "What is the FIRST step in AWS cost optimization?",
    options: [
        "Enable Cost Explorer and analyze spending patterns",
        "Buy Reserved Instances immediately",
        "Terminate all resources and rebuild",
        "Switch to Spot Instances"
    ],
    correct: 0,
    explanation: {
        correct: "Cost Explorer provides visibility into spending patterns, essential for identifying optimization opportunities before making changes.",
        whyWrong: {
            1: "Buying RIs without analysis may purchase wrong types",
            2: "Terminating everything is disruptive and risky",
            3: "Spot Instances without analysis may not suit workloads"
        },
        examStrategy: "Analyze before optimizing. Cost Explorer for spending visibility. Data-driven optimization decisions."
    }
},
{
    id: 'cost_067',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company has 50TB in S3 Standard costing $1,150/month. The data is uploaded once and never accessed again but must be retained for compliance.",
    question: "Which storage class reduces costs the MOST for this write-once, never-read pattern?",
    options: [
        "S3 Glacier Deep Archive at $50/month",
        "S3 Standard-IA at $640/month",
        "S3 Glacier Flexible at $200/month",
        "S3 Intelligent-Tiering"
    ],
    correct: 0,
    explanation: {
        correct: "Glacier Deep Archive at $0.00099/GB/month is ideal for compliance data that's never accessed, saving 95% over Standard.",
        whyWrong: {
            1: "Standard-IA still expensive for never-accessed data",
            2: "Glacier Flexible more expensive than Deep Archive",
            3: "Intelligent-Tiering has monitoring fees and higher base cost"
        },
        examStrategy: "Deep Archive for compliance/never-accessed data. 95% savings over Standard. Lowest storage cost in AWS."
    }
},
{
    id: 'cost_068',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A multi-tenant SaaS platform has varying resource usage per customer. Top 10% of customers use 90% of resources but pay the same subscription.",
    question: "Which architecture enables usage-based cost allocation and pricing?",
    options: [
        "Separate AWS accounts per customer with consolidated billing and cost allocation tags",
        "Single account with all customers",
        "Different regions for different customers",
        "Dedicated instances for large customers only"
    ],
    correct: 0,
    explanation: {
        correct: "Account separation enables precise cost tracking per customer, tags enable grouping, supporting usage-based pricing models.",
        whyWrong: {
            1: "Single account makes cost attribution difficult",
            2: "Regional separation doesn't solve cost allocation",
            3: "Dedicated instances don't track all resource usage"
        },
        examStrategy: "Account separation for cost attribution. Tags for cost allocation. Enable usage-based pricing with visibility."
    }
},
{
    id: 'cost_069',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company's Redshift cluster costs $30K/month but CPU utilization averages 20% with occasional spikes to 80%.",
    question: "Which strategy optimizes Redshift costs for this usage pattern?",
    options: [
        "Use Redshift Serverless with RPU scaling for variable workloads",
        "Add more nodes to reduce CPU utilization",
        "Purchase Reserved Instances for current cluster",
        "Implement result caching only"
    ],
    correct: 0,
    explanation: {
        correct: "Redshift Serverless charges only for actual usage, ideal for variable workloads with low average utilization.",
        whyWrong: {
            1: "More nodes increase costs with already low utilization",
            2: "RIs lock in costs for underutilized cluster",
            3: "Result caching helps but doesn't address core underutilization"
        },
        examStrategy: "Serverless for variable workloads. Pay-per-use when utilization is low. Provisioned for steady-state workloads."
    }
},
{
    id: 'cost_070',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A startup wants to experiment with AWS services but is concerned about unexpected costs.",
    question: "Which feature prevents unexpected charges by stopping resources at a threshold?",
    options: [
        "AWS Budgets with actions to stop resources",
        "Cost Explorer recommendations",
        "Trusted Advisor checks",
        "CloudWatch billing alarms only"
    ],
    correct: 0,
    explanation: {
        correct: "AWS Budgets with actions can automatically stop or terminate resources when spending thresholds are reached.",
        whyWrong: {
            1: "Cost Explorer provides recommendations but no automatic actions",
            2: "Trusted Advisor identifies issues but doesn't stop resources",
            3: "Billing alarms notify but don't take action"
        },
        examStrategy: "AWS Budgets for cost control with actions. Set conservative thresholds for experimentation. Automatic enforcement over manual."
    }
},
{
    id: 'cost_071',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company processes 1 million images monthly using Lambda. Current cost: $5,000/month. Processing time: 3 seconds per image at 3GB memory.",
    question: "Which optimization could reduce Lambda costs by 50%?",
    options: [
        "Reduce memory to 1GB if processing time increases to only 6 seconds",
        "Increase memory to 10GB to reduce time to 1 second",
        "Use EC2 instead of Lambda",
        "Process images in batches of 100"
    ],
    correct: 0,
    explanation: {
        correct: "Lambda pricing is memory × duration. 1GB×6s = 6GB-seconds vs 3GB×3s = 9GB-seconds, saving 33% per invocation.",
        whyWrong: {
            1: "10GB×1s = 10GB-seconds, more expensive than current",
            2: "EC2 requires management and may not be cheaper",
            3: "Batching doesn't reduce total compute needed"
        },
        examStrategy: "Lambda cost = memory × duration. Sometimes less memory is cheaper despite longer runtime. Test different configurations."
    }
},
{
    id: 'cost_072',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company has $500K annual AWS spend across 10 accounts with varying workload patterns and 3-year growth projection of 300%.",
    question: "Which commitment strategy provides the BEST long-term cost optimization?",
    options: [
        "1-year Compute Savings Plans for baseline, re-evaluate annually for growth",
        "3-year Reserved Instances for everything",
        "Stay on On-Demand for flexibility",
        "3-year Savings Plans for projected peak"
    ],
    correct: 0,
    explanation: {
        correct: "1-year commitments provide savings while maintaining flexibility for growth, annual re-evaluation adapts to changing needs.",
        whyWrong: {
            1: "3-year RIs lack flexibility for 300% growth",
            2: "On-Demand most expensive option",
            3: "Committing to projected peak wastes money initially"
        },
        examStrategy: "Shorter commitments for growing companies. Regular re-evaluation of commitments. Balance savings with flexibility."
    }
},
{
    id: 'cost_073',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs 100TB of file storage accessible by 1000 EC2 instances. Currently using EBS with snapshots, costing $15K/month.",
    question: "Which storage solution reduces costs while maintaining functionality?",
    options: [
        "EFS with lifecycle management to Infrequent Access storage class",
        "Individual EBS volumes for each instance",
        "S3 with VPC endpoint",
        "FSx for Windows File Server"
    ],
    correct: 0,
    explanation: {
        correct: "EFS provides shared storage for all instances, lifecycle management automatically moves cold data to IA saving 90% on storage costs.",
        whyWrong: {
            1: "Individual EBS volumes multiply costs by instance count",
            2: "S3 not suitable for file system workloads",
            3: "FSx for Windows more expensive than EFS"
        },
        examStrategy: "EFS for shared file storage. Lifecycle management for automatic cost optimization. IA storage class for infrequently accessed data."
    }
},
{
    id: 'cost_074',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company's CloudWatch costs are high due to detailed monitoring on all EC2 instances.",
    question: "How can CloudWatch costs be reduced without losing critical monitoring?",
    options: [
        "Use basic monitoring for non-production, detailed only for production",
        "Disable all CloudWatch monitoring",
        "Switch to third-party monitoring",
        "Create custom metrics for everything"
    ],
    correct: 0,
    explanation: {
        correct: "Basic monitoring is free and sufficient for non-production, detailed monitoring only where needed reduces costs.",
        whyWrong: {
            1: "Disabling all monitoring risks blind spots",
            2: "Third-party tools may cost more",
            3: "Custom metrics increase costs"
        },
        examStrategy: "Basic monitoring is free and often sufficient. Detailed monitoring only for critical resources. Reduce metric frequency where possible."
    }
},
{
    id: 'cost_075',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company runs disaster recovery infrastructure in a second region, costing $40K/month but only used during quarterly DR tests.",
    question: "Which DR strategy maintains readiness while reducing costs?",
    options: [
        "Pilot light with automated CloudFormation for rapid scaling during tests/disasters",
        "Keep full infrastructure running 24/7",
        "No DR infrastructure, rebuild when needed",
        "On-premises DR instead of cloud"
    ],
    correct: 0,
    explanation: {
        correct: "Pilot light keeps minimal core components running (10% cost) with automation to quickly provision full environment when needed.",
        whyWrong: {
            1: "Full infrastructure wastes money for quarterly use",
            2: "No DR infrastructure risks long recovery time",
            3: "On-premises DR requires capital investment"
        },
        examStrategy: "Pilot light for cost-effective DR. Automation enables rapid scaling. Balance cost with recovery time requirements."
    }
},
{
    id: 'cost_076',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company spends $200K/month on AWS: 40% compute, 30% storage, 20% database, 10% network. They need to reduce costs by 30% in 90 days.",
    question: "Which strategy achieves 30% cost reduction fastest?",
    options: [
        "Right-size compute, implement S3 lifecycle policies, and purchase Savings Plans for remaining baseline",
        "Negotiate Enterprise Discount Program with AWS",
        "Migrate everything to Spot Instances",
        "Reduce service usage by 30% across the board"
    ],
    correct: 0,
    explanation: {
        correct: "Combined approach: right-sizing can save 20-30% on compute, lifecycle policies 50% on storage, Savings Plans 20% on baseline.",
        whyWrong: {
            1: "EDP negotiations take time and require higher spend",
            2: "Spot Instances unsuitable for all workloads",
            3: "Reducing usage may impact business operations"
        },
        examStrategy: "Multiple optimization strategies in parallel. Quick wins first (right-sizing). Savings Plans for immediate discounts."
    }
},
{
    id: 'cost_077',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A gaming company has highly variable traffic: 1000 concurrent users normally, 50,000 during game launches lasting 2 weeks.",
    question: "Which architecture minimizes costs for this variable pattern?",
    options: [
        "Baseline Reserved Instances + Spot Fleet for launches with fallback to On-Demand",
        "Size for peak with Reserved Instances",
        "All On-Demand with Auto Scaling",
        "Scheduled Reserved Instances for launches"
    ],
    correct: 0,
    explanation: {
        correct: "RIs for baseline minimize normal costs, Spot Fleet provides cheap capacity for launches, On-Demand ensures availability.",
        whyWrong: {
            1: "Peak sizing wastes money 50 weeks per year",
            2: "All On-Demand is most expensive option",
            3: "Scheduled RIs discontinued, can't schedule for sporadic launches"
        },
        examStrategy: "Layer capacity types: RI baseline, Spot for variable, On-Demand for overflow. Match purchasing to usage patterns."
    }
},
{
    id: 'cost_078',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company is paying for multiple overlapping AWS support plans across different accounts.",
    question: "How can support plan costs be optimized?",
    options: [
        "Consolidate under AWS Organizations with single support plan",
        "Remove all support plans",
        "Upgrade all to Enterprise support",
        "Keep separate plans for isolation"
    ],
    correct: 0,
    explanation: {
        correct: "Organizations allows sharing a single support plan across all member accounts, eliminating duplicate costs.",
        whyWrong: {
            1: "No support limits AWS assistance",
            2: "Enterprise for all accounts very expensive",
            3: "Separate plans waste money on overlap"
        },
        examStrategy: "Consolidate support plans under Organizations. Single plan covers all member accounts. Choose appropriate level for needs."
    }
},
{
    id: 'cost_079',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs to process 10TB of data monthly through a complex ML pipeline. Currently using SageMaker on-demand at $8K/month.",
    question: "Which approach reduces ML processing costs while maintaining capabilities?",
    options: [
        "SageMaker Savings Plans with Spot training instances for non-critical experiments",
        "Move to Lambda functions",
        "Build custom ML on EC2",
        "Use only SageMaker Free Tier"
    ],
    correct: 0,
    explanation: {
        correct: "SageMaker Savings Plans provide 64% discount, Spot training instances add 90% discount for fault-tolerant training jobs.",
        whyWrong: {
            1: "Lambda unsuitable for large-scale ML training",
            2: "Custom EC2 requires significant management overhead",
            3: "Free Tier insufficient for 10TB processing"
        },
        examStrategy: "SageMaker Savings Plans for ML workloads. Spot for training when possible. Managed services reduce operational costs."
    }
},
{
    id: 'cost_080',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company has 1PB of data across S3, EBS, and RDS. Backup costs are $100K/month using AWS Backup with daily backups retained for 30 days.",
    question: "Which backup strategy reduces costs while maintaining protection?",
    options: [
        "Grandfather-father-son rotation: daily for 7 days, weekly for 4 weeks, monthly for 12 months",
        "Daily backups forever",
        "No backups, rely on service durability",
        "Hourly backups for everything"
    ],
    correct: 0,
    explanation: {
        correct: "GFS rotation reduces storage by 70% while maintaining point-in-time recovery options with longer-term protection.",
        whyWrong: {
            1: "Daily forever exponentially increases costs",
            2: "No backups risks data loss from logical errors",
            3: "Hourly backups dramatically increase costs"
        },
        examStrategy: "GFS rotation balances protection with cost. Reduce backup frequency over time. Match retention to actual recovery needs."
    }
},
{
    id: 'cost_081',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company runs 50 development databases on RDS, each used only during business hours. Monthly cost: $25K.",
    question: "Which approach provides the GREATEST cost savings for development databases?",
    options: [
        "Aurora Serverless v2 with scale-to-zero during off-hours",
        "Keep RDS but purchase Reserved Instances",
        "Manually stop/start each RDS instance",
        "Consolidate all databases into one large instance"
    ],
    correct: 0,
    explanation: {
        correct: "Aurora Serverless v2 automatically scales to zero during inactivity, eliminating costs during nights/weekends (70% savings).",
        whyWrong: {
            1: "RIs charge 24/7, no savings for partial use",
            2: "Manual stop/start is error-prone for 50 databases",
            3: "Consolidation creates dependencies and conflicts"
        },
        examStrategy: "Aurora Serverless for variable development workloads. Scale-to-zero for unused periods. Automatic better than manual."
    }
},
{
    id: 'cost_082',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company wants to prevent developers from launching expensive instance types like x1e.32xlarge.",
    question: "How can expensive instance types be restricted?",
    options: [
        "Service Control Policy denying ec2:RunInstances for specific instance types",
        "Remove the instance types from the console",
        "Email policy to all developers",
        "Monitor and terminate after launch"
    ],
    correct: 0,
    explanation: {
        correct: "SCPs provide preventive controls, blocking the launch of expensive instance types at the organization level.",
        whyWrong: {
            1: "Can't remove instance types from console",
            2: "Email policies often ignored",
            3: "Terminate after launch still incurs initial costs"
        },
        examStrategy: "SCPs for preventive cost controls. Block expensive resources at launch. Prevent rather than detect and fix."
    }
},
{
    id: 'cost_083',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A media company stores 500TB of video content. 10TB is accessed daily, 50TB monthly, remainder accessed yearly.",
    question: "Which S3 storage strategy minimizes costs for this access pattern?",
    options: [
        "S3 Standard for 10TB, Standard-IA for 50TB, Glacier Instant Retrieval for remainder",
        "All in S3 Standard for simplicity",
        "All in Glacier Deep Archive for lowest cost",
        "S3 Intelligent-Tiering for everything"
    ],
    correct: 0,
    explanation: {
        correct: "Tiering by access frequency: Standard for daily (10TB), IA for monthly (50TB), Glacier Instant for yearly (440TB) optimizes costs.",
        whyWrong: {
            1: "All Standard wastes money on rarely accessed content",
            2: "All Glacier makes daily content inaccessible",
            3: "Intelligent-Tiering fees add up at 500TB scale"
        },
        examStrategy: "Manual tiering for predictable access patterns. Match storage class to access frequency. Avoid Intelligent-Tiering fees at scale."
    }
},
{
    id: 'cost_084',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A SaaS company needs to optimize costs across 500 microservices with different resource patterns. Current: $300K/month, 60% waste identified.",
    question: "Which modernization strategy provides the best cost optimization?",
    options: [
        "Container right-sizing with Fargate Spot for stateless services and ECS capacity providers",
        "Rewrite everything in Lambda",
        "Move all to Kubernetes",
        "Keep current architecture, buy Reserved Instances"
    ],
    correct: 0,
    explanation: {
        correct: "Container right-sizing eliminates waste, Fargate Spot saves 70% for stateless, capacity providers optimize instance utilization.",
        whyWrong: {
            1: "Lambda rewrite massive effort, not suitable for all services",
            2: "Kubernetes alone doesn't reduce costs",
            3: "RIs on wasteful infrastructure perpetuates inefficiency"
        },
        examStrategy: "Right-size containers first. Fargate Spot for stateless workloads. Capacity providers for EC2 efficiency."
    }
},
{
    id: 'cost_085',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs to reduce data transfer costs between their on-premises data center and AWS, currently $30K/month.",
    question: "Which solution provides the MOST cost-effective data transfer?",
    options: [
        "AWS Direct Connect with virtual interfaces to VPCs",
        "Increase internet bandwidth",
        "Compress all data before transfer",
        "Use Snow devices for all transfers"
    ],
    correct: 0,
    explanation: {
        correct: "Direct Connect provides reduced data transfer rates compared to internet, paying for itself at $30K/month transfer costs.",
        whyWrong: {
            1: "Internet bandwidth doesn't reduce AWS transfer charges",
            2: "Compression helps but doesn't address rate costs",
            3: "Snow devices for regular transfers impractical"
        },
        examStrategy: "Direct Connect for high-volume regular transfers. Lower per-GB rates than internet. Break-even analysis for connection costs."
    }
},
{
    id: 'cost_086',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company has numerous forgotten AWS resources from proof-of-concepts accumulating costs.",
    question: "What is the BEST way to identify and clean up unused resources?",
    options: [
        "AWS Resource Groups with tag-based lifecycle automation",
        "Manual monthly reviews",
        "Delete everything and start over",
        "Ignore small resources"
    ],
    correct: 0,
    explanation: {
        correct: "Resource Groups with tags enable identifying POC resources and automating cleanup based on age or tags.",
        whyWrong: {
            1: "Manual reviews miss resources and are time-consuming",
            2: "Deleting everything risks production impact",
            3: "Small resources accumulate to significant costs"
        },
        examStrategy: "Tag resources at creation. Automate cleanup based on tags. Resource Groups for organization and automation."
    }
},
{
    id: 'cost_087',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company runs analytics on 100TB of data quarterly. Currently keeping EMR cluster running 24/7 at $40K/month.",
    question: "Which approach reduces costs for quarterly analytics?",
    options: [
        "Transient EMR clusters with S3 data lake, launched only for quarterly processing",
        "Keep EMR running but use smaller instances",
        "Reserved Instances for EMR cluster",
        "Move to real-time analytics"
    ],
    correct: 0,
    explanation: {
        correct: "Transient clusters eliminate 11 months of unnecessary costs, S3 data lake provides persistent storage at low cost.",
        whyWrong: {
            1: "Smaller instances still run unnecessarily for 9 months",
            2: "RIs lock in costs for barely-used cluster",
            3: "Real-time increases costs for quarterly needs"
        },
        examStrategy: "Transient clusters for periodic workloads. S3 as data lake. Pay only for actual processing time."
    }
},
{
    id: 'cost_088',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A global enterprise has $5M annual AWS spend across 100 accounts with no governance. Estimated 40% waste from redundant resources.",
    question: "Which governance structure provides the best cost optimization?",
    options: [
        "Control Tower with AWS Organizations, SCPs, and standardized account factory with cost controls",
        "Continue with independent accounts",
        "Consolidate everything into one account",
        "Manual review of each account monthly"
    ],
    correct: 0,
    explanation: {
        correct: "Control Tower provides governance framework, Organizations enables consolidated billing and volume discounts, SCPs enforce cost policies.",
        whyWrong: {
            1: "Independent accounts miss volume discounts and lack control",
            2: "Single account creates security and operational risks",
            3: "Manual reviews don't scale to 100 accounts"
        },
        examStrategy: "Control Tower for multi-account governance. Organizations for cost consolidation. SCPs for preventive controls."
    }
},
{
    id: 'cost_089',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs to optimize their containerized workloads. Currently running 200 containers on 50 m5.xlarge instances with 30% CPU utilization.",
    question: "Which optimization provides the best cost reduction?",
    options: [
        "ECS with bin packing placement strategy on fewer, larger instances",
        "Move all containers to Lambda",
        "Keep current setup but add more containers",
        "Switch to Kubernetes"
    ],
    correct: 0,
    explanation: {
        correct: "Bin packing consolidates containers efficiently, reducing instance count by 60% while maintaining performance.",
        whyWrong: {
            1: "Lambda not suitable for all container workloads",
            2: "Adding containers without optimization doesn't reduce costs",
            3: "Kubernetes alone doesn't improve utilization"
        },
        examStrategy: "Bin packing for container consolidation. Fewer, larger instances often more cost-effective. ECS placement strategies for optimization."
    }
},
{
    id: 'cost_090',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company wants to track and optimize their AWS costs by department.",
    question: "What is the BEST way to allocate costs to departments?",
    options: [
        "Use cost allocation tags and Cost Explorer filtering",
        "Separate AWS account for each department",
        "Manual spreadsheet tracking",
        "Single monthly bill review"
    ],
    correct: 0,
    explanation: {
        correct: "Cost allocation tags enable departmental cost tracking within Cost Explorer without account separation complexity.",
        whyWrong: {
            1: "Separate accounts add management overhead",
            2: "Manual tracking is error-prone",
            3: "Single bill doesn't show departmental breakdown"
        },
        examStrategy: "Cost allocation tags for organizational cost tracking. Activate tags in billing console. Use Cost Explorer for analysis."
    }
},
{
    id: 'cost_091',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company processes customer data in batches overnight. Jobs take 4-8 hours on 20 r5.4xlarge instances costing $15K/month.",
    question: "Which optimization reduces batch processing costs the MOST?",
    options: [
        "Spot Fleet with instance weighting across r5, r4, and m5 families",
        "Reserved Instances for all 20 instances",
        "Reduce to 10 instances running longer",
        "Switch to on-demand pricing"
    ],
    correct: 0,
    explanation: {
        correct: "Spot Fleet with multiple families ensures capacity while saving up to 90% on batch processing costs.",
        whyWrong: {
            1: "RIs still charge for unused daytime hours",
            2: "Fewer instances may not complete in time window",
            3: "On-demand is current pricing, no savings"
        },
        examStrategy: "Spot Fleet for batch workloads. Instance diversification ensures capacity. 90% savings possible with Spot."
    }
},
{
    id: 'cost_092',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company has complex licensing requirements: 100 Oracle licenses, 200 Windows licenses, 500 RHEL subscriptions. Annual license costs: $2M.",
    question: "Which strategy optimizes license costs in AWS?",
    options: [
        "Dedicated Hosts for Oracle/Windows BYOL, RHEL on-demand for flexibility",
        "All license-included instances",
        "All BYOL on Dedicated Hosts",
        "Avoid licensed software completely"
    ],
    correct: 0,
    explanation: {
        correct: "Dedicated Hosts enable BYOL for expensive Oracle/Windows licenses, RHEL on-demand provides flexibility without host commitment.",
        whyWrong: {
            1: "License-included doubles costs for owned licenses",
            2: "All Dedicated Hosts overcommits for RHEL",
            3: "Avoiding licensed software may not be feasible"
        },
        examStrategy: "BYOL for expensive licenses on Dedicated Hosts. On-demand for commodity licenses. Balance commitment with flexibility."
    }
},
{
    id: 'cost_093',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company's DynamoDB tables cost $20K/month. Analysis shows 80% of capacity consumed by a single hot partition key.",
    question: "Which optimization reduces DynamoDB costs while maintaining performance?",
    options: [
        "Redesign partition key strategy to distribute load evenly",
        "Increase provisioned capacity",
        "Switch to on-demand pricing",
        "Add Global Secondary Index"
    ],
    correct: 0,
    explanation: {
        correct: "Proper partition key design distributes load evenly, reducing required capacity by up to 80% while improving performance.",
        whyWrong: {
            1: "Increasing capacity wastes money on unused partitions",
            2: "On-demand still expensive with poor key design",
            3: "GSI doesn't fix hot partition in main table"
        },
        examStrategy: "Partition key design crucial for DynamoDB costs. Even distribution reduces capacity needs. Fix design before scaling."
    }
},
{
    id: 'cost_094',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A company wants to reduce costs but needs approval before making any changes.",
    question: "Which AWS service provides cost optimization recommendations without automatic changes?",
    options: [
        "AWS Compute Optimizer",
        "AWS Auto Scaling",
        "AWS Systems Manager Automation",
        "AWS Lambda scheduled functions"
    ],
    correct: 0,
    explanation: {
        correct: "Compute Optimizer provides recommendations for right-sizing without making automatic changes, requiring manual approval.",
        whyWrong: {
            1: "Auto Scaling makes automatic changes",
            2: "Systems Manager Automation executes changes",
            3: "Lambda functions would execute changes"
        },
        examStrategy: "Compute Optimizer for recommendations. Review before implementing. Data-driven optimization decisions."
    }
},
{
    id: 'cost_095',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company runs 1000 Lambda functions with varying execution patterns. Monthly cost: $30K with 60% from idle provisioned concurrency.",
    question: "Which optimization reduces Lambda costs while maintaining performance?",
    options: [
        "Remove provisioned concurrency for functions with <100 invocations/day, use only for high-frequency",
        "Add provisioned concurrency to all functions",
        "Convert all to EC2 instances",
        "Increase memory for all functions"
    ],
    correct: 0,
    explanation: {
        correct: "Provisioned concurrency costs even when idle; removing from low-frequency functions saves 60% while maintaining performance where needed.",
        whyWrong: {
            1: "More provisioned concurrency increases costs",
            2: "EC2 conversion loses serverless benefits",
            3: "Memory increases may not offset provisioned costs"
        },
        examStrategy: "Provisioned concurrency only for high-frequency functions. Regular Lambda for sporadic workloads. Match configuration to usage."
    }
},
{
    id: 'cost_096',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company needs to optimize their entire AWS infrastructure. Current: $1M/month across compute, storage, database, and networking.",
    question: "What is the CORRECT order of optimization actions for maximum impact?",
    options: [
        "1) Right-size resources, 2) Purchase Savings Plans, 3) Optimize storage classes, 4) Review network architecture",
        "1) Buy Reserved Instances, 2) Delete unused resources, 3) Compress data, 4) Add caching",
        "1) Migrate to Spot, 2) Reduce service usage, 3) Negotiate discounts, 4) Consolidate accounts",
        "1) Switch regions, 2) Change instance families, 3) Add monitoring, 4) Implement chargebacks"
    ],
    correct: 0,
    explanation: {
        correct: "Right-sizing provides immediate savings and informs Savings Plans purchases, storage optimization is next biggest impact, network last.",
        whyWrong: {
            1: "Buying RIs before right-sizing wastes money",
            2: "Spot migration not suitable for all workloads",
            3: "Region switching may impact performance"
        },
        examStrategy: "Optimization order: waste elimination → commitment discounts → storage optimization → network optimization."
    }
},
{
    id: 'cost_097',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs to reduce RDS costs. They have 50 instances with 30% average CPU usage and automatic backups retained for 35 days.",
    question: "Which combination provides the BEST cost optimization?",
    options: [
        "Consolidate databases where possible, reduce backup retention to 7 days, purchase Reserved Instances",
        "Keep all separate, increase backup retention",
        "Move everything to DynamoDB",
        "Upgrade all instances for better performance"
    ],
    correct: 0,
    explanation: {
        correct: "Consolidation reduces instance count, shorter retention reduces backup storage, RIs provide additional discount on optimized infrastructure.",
        whyWrong: {
            1: "Longer retention increases costs",
            2: "DynamoDB migration complex and may cost more",
            3: "Upgrading increases costs with low utilization"
        },
        examStrategy: "Consolidate underutilized databases. Optimize backup retention. Apply RIs after right-sizing."
    }
},
{
    id: 'cost_098',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "easy",
    timeRecommendation: 90,
    scenario: "A developer accidentally left an expensive GPU instance running for a month, costing $5,000.",
    question: "What prevents similar incidents in the future?",
    options: [
        "Automated termination policy based on idle time and tags",
        "Remove GPU instance permissions",
        "Daily email reminders",
        "Larger budget to accommodate mistakes"
    ],
    correct: 0,
    explanation: {
        correct: "Automated termination based on idle metrics and tags prevents forgotten instances from accumulating costs.",
        whyWrong: {
            1: "Removing permissions impacts legitimate use",
            2: "Email reminders often ignored",
            3: "Larger budget doesn't prevent waste"
        },
        examStrategy: "Automate cost controls. Tag-based governance. Terminate idle resources automatically."
    }
},
{
    id: 'cost_099',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "medium",
    timeRecommendation: 120,
    scenario: "A company needs to optimize their API Gateway costs, currently at $10K/month for 1 billion requests.",
    question: "Which optimization strategy reduces API Gateway costs?",
    options: [
        "Implement caching for frequently accessed endpoints and consider HTTP APIs for simple use cases",
        "Add more REST APIs",
        "Increase throttling limits",
        "Remove all caching"
    ],
    correct: 0,
    explanation: {
        correct: "Caching reduces backend calls and costs, HTTP APIs cost 70% less than REST APIs for simple use cases.",
        whyWrong: {
            1: "More REST APIs increase costs",
            2: "Throttling limits don't reduce per-request costs",
            3: "Removing caching increases backend calls and costs"
        },
        examStrategy: "API Gateway caching for cost reduction. HTTP APIs cheaper than REST APIs. Cache frequently accessed data."
    }
},
{
    id: 'cost_100',
    domain: "Domain 4: Design Cost-Optimized Architectures",
    difficulty: "hard",
    timeRecommendation: 150,
    scenario: "A company completed a cloud migration but costs are 40% higher than on-premises. They're using cloud resources like on-premises servers.",
    question: "Which cloud-native transformation provides the GREATEST cost optimization?",
    options: [
        "Refactor monoliths to microservices, implement auto-scaling, use managed services, adopt serverless where appropriate",
        "Keep lift-and-shift architecture, buy more Reserved Instances",
        "Move back to on-premises",
        "Negotiate better AWS pricing"
    ],
    correct: 0,
    explanation: {
        correct: "Cloud-native architecture leverages auto-scaling, managed services reduce operational overhead, serverless eliminates idle capacity costs.",
        whyWrong: {
            1: "Lift-and-shift doesn't leverage cloud benefits",
            2: "Moving back loses cloud advantages",
            3: "Pricing negotiations don't fix architectural inefficiencies"
        },
        examStrategy: "Cloud-native architecture for cost optimization. Auto-scaling for elasticity. Managed services reduce TCO. Serverless for variable workloads."
    }
}
    ]
            
 };

// Append the additional questions to your existing questionBank
// Add to security array
questionBank.security.push(...additionalSecurityQuestions);

// Add to resilience array  
questionBank.resilience.push(...additionalResilienceQuestions);

// Add to performance array
questionBank.performance.push(...additionalPerformanceQuestions);

// Add to cost array
questionBank.cost.push(...additionalCostQuestions);

// Update the statistics
const totalQuestions = 
    questionBank.security.length + 
    questionBank.resilience.length + 
    questionBank.performance.length + 
    questionBank.cost.length;

console.log('🎯 SAA-C03 Question Bank Updated');
console.log(`📊 Questions by Domain:`);
console.log(`   • Security: ${questionBank.security.length} questions`);
console.log(`   • Resilience: ${questionBank.resilience.length} questions`);
console.log(`   • Performance: ${questionBank.performance.length} questions`);
console.log(`   • Cost: ${questionBank.cost.length} questions`);
console.log(`📈 Total: ${totalQuestions} questions`);


const questionBank = { security, resilience, performance, cost };
// Make questionBank available globally
window.questionBank = questionBank;

// Calculate and display statistics
const stats = {
    security: questionBank.security.length,
    resilience: questionBank.resilience.length,
    performance: questionBank.performance.length,
    cost: questionBank.cost.length,
    total: 0
};

stats.total = stats.security + stats.resilience + stats.performance + stats.cost;

console.log('🎯 SAA-C03 Question Bank Loaded Successfully!');
console.log('📊 Domain Distribution:');
console.log(`   • Domain 1 (Security): ${stats.security} questions (${(stats.security/5).toFixed(0)}%) - Target: 30%`);
console.log(`   • Domain 2 (Resilience): ${stats.resilience} questions (${(stats.resilience/5).toFixed(0)}%) - Target: 26%`);
console.log(`   • Domain 3 (Performance): ${stats.performance} questions (${(stats.performance/5).toFixed(0)}%) - Target: 24%`);
console.log(`   • Domain 4 (Cost): ${stats.cost} questions (${(stats.cost/5).toFixed(0)}%) - Target: 20%`);
console.log(`📈 Total Questions: ${stats.total} / 500`);

// Display warning if not enough questions
if (stats.total < 500) {
    console.warn(`⚠️ Need ${500 - stats.total} more questions to reach 500 total.`);
    console.log('💡 Tip: You can add more questions to each domain following the same format.');
}
