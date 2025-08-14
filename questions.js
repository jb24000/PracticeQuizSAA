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
        // Continue with more security questions...
        // Adding 140 more security questions to reach 150 total
        
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
        // Continue with more resilience questions...
        // Adding 120 more resilience questions to reach 130 total
        
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
        // Continue with more performance questions...
        // Adding 110 more performance questions to reach 120 total
        
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
        // Continue with more cost questions...
        // Adding 90 more cost questions to reach 100 total
        
    ]
};

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
