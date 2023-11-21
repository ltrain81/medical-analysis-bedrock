from aws_cdk import core, aws_s3 as s3, aws_lambda as _lambda, aws_dynamodb as dynamodb, aws_iam as iam, aws_opensearchservice as opensearch, aws_lambda_event_sources as lambda_events, aws_secretsmanager as secretsmanager

class MedicalAnalysisStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        
        account_id = core.Aws.ACCOUNT_ID
        bucket_name = f"Medical-Analysis-Bedrock-{account_id}"
        
        # Create S3 bucket
        medical_bucket = s3.Bucket(
            self, "MedicalBucket",
            bucket_name=bucket_name
        )
        
        open_search_credentials = secretsmanager.Secret(
            self, "OpenSearchCredentials",
            secret_name="MyOpenSearchCredentials",
            description="Credentials for OpenSearch domain",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username": "admin"}',
                generate_string_key="password",
                exclude_punctuation=True,
                password_length=16
            )
        )

        username = open_search_credentials.secret_value_from_json("username").to_string()
        password = open_search_credentials.secret_value_from_json("password").to_string()

        # Create folders inside the bucket
        audio_emr_folder = medical_bucket.add_folder("audioEMR")
        text_emr_folder = medical_bucket.add_folder("textEMR")
        audio_emr_folder.add_folder("raw-audio")
        audio_emr_folder.add_folder("transcribe-output")
        audio_emr_folder.add_folder("transcript-txt")
        
        # Create DynamoDB table
        medical_table = dynamodb.Table(
            self, "MedicalTable",
            table_name="MedicalTable",
            partition_key=dynamodb.Attribute(
                name="DiagnosisID",
                type=dynamodb.AttributeType.STRING
            )
        )
        
        medical_domain = opensearch.Domain(
            self, "MedicalDomain",
            domain_name="medical-domain",
            version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
            capacity={
                "master_nodes": 1,
                "data_nodes": 2
            },
            zone_awareness=opensearch.ZoneAwarenessConfig(
                availability_zone_count=2
            ),
            ebs=opensearch.EbsOptions(
                volume_size=20
            ),
            access_policy=opensearch.AwsJsonPolicy.from_statements([
                opensearch.PolicyStatement(
                    actions=["es:*"],
                    principals=["*"],
                    effect=opensearch.Effect.ALLOW,
                    resources=["*"]
                )
            ]),
            encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True),
            node_to_node_encryption=opensearch.NodeToNodeEncryptionOptions(enabled=True),
            fine_grained_access_control=opensearch.AdvancedSecurityOptions(
                master_user_options={
                    "master_user_name": username,  # Set the master username
                    "master_user_password": password  # Set the master password
                },
                internal_user_database_options={
                    "enabled": True
                }
            )
            # Define other properties of the OpenSearch domain as needed
        )
        
        # Create IAM role for AudioToTranscribe Lambda with required permissions
        audio_to_transcribe_role = iam.Role(
            self, "AudioToTranscribeRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="AudioToTranscribeRole",
        )

        # Create IAM role for TranscriptToTxt Lambda with required permissions
        transcript_to_txt_role = iam.Role(
            self, "TranscriptToTxtRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="TranscriptToTxtRole",
        )

        # Attach policies to transcript_to_txt_role
        transcript_to_txt_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],  # Example action, adjust as needed
                resources=[medical_bucket.bucket_arn + "/audioEMR/transcribe-output/*"],
            )
        )
        # Add more permissions as needed for TranscriptToTxt Lambda

        # Create IAM role for Medical-Bedrock Lambda with required permissions
        medical_bedrock_role = iam.Role(
            self, "MedicalBedrockRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="MedicalBedrockRole",
        )

        # Attach policies to medical_bedrock_role
        medical_bedrock_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject", "s3:PutObject", "dynamodb:PutItem"],  # Example actions, adjust as needed
                resources=[
                    medical_bucket.bucket_arn + "/audioEMR/transcript-txt/*",
                    medical_table.table_arn,
                ],
            )
        )

        # Create IAM role for DDBtoOpensearch Lambda with required permissions
        ddb_to_opensearch_role = iam.Role(
            self, "DDBtoOpensearchRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="DDBtoOpensearchRole",
        )

        # Attach policies to ddb_to_opensearch_role
        ddb_to_opensearch_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["dynamodb:*"],  # Example action, adjust as needed
                resources=[medical_table.table_arn],
            )
        )

        # Attach policies to audio_to_transcribe_role
        audio_to_transcribe_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:*"],
                resources=[medical_bucket.bucket_arn + "/audioEMR/raw-audio/*"],
            )
        )
        audio_to_transcribe_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["transcribe:StartTranscriptionJob"],  # Example action, adjust as needed
                resources=["*"],  # Limit to specific resource if possible
            )
        )

        # Use existing Lambda code for AudioToTranscribe Lambda
        audio_to_transcribe_code_path = "lambda/AudioToTranscribe.zip"  # Replace with your path
        audio_to_transcribe_lambda = _lambda.Function(
            self, "AudioToTranscribe",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(audio_to_transcribe_code_path),
            timeout=core.Duration.minutes(3),
            role=audio_to_transcribe_role
        )

        # Create Lambda function for TranscriptToTxt
        transcript_to_txt_lambda_code_path = "lambda/TranscriptToTxt.zip"
        transcript_to_txt_lambda = _lambda.Function(
            self, "TranscriptToTxt",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(transcript_to_txt_lambda_code_path),  # Replace with your path
            timeout=core.Duration.minutes(3),
            role=transcript_to_txt_role,  # Assign the previously defined IAM role
        )
        # Add trigger for transcript_to_txt_lambda (S3 Put trigger for audioEMR/transcribe-output)


        boto3_mylayer = _lambda.LayerVersion(
            self, "Boto3MyLayer",
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_9],  # Specify the runtime
            code=_lambda.Code.from_asset("lambda/boto3-mylayer.zip")  # Replace with your layer code path
        )

        requests_layer = _lambda.LayerVersion(
            self, "RequestLayer",
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_9],
            code=_lambda.Code.from_asset("lambda/requests.zip")
        )

        # Create Lambda function for Medical-Bedrock
        medical_bedrock_path = "lambda/medical-bedrock.zip"
        medical_bedrock_lambda = _lambda.Function(
            self, "MedicalBedrock",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(medical_bedrock_path),  # Replace with your path
            timeout=core.Duration.minutes(3),
            role=medical_bedrock_role,  # Assign the previously defined IAM role
            layers=[boto3_mylayer]
        )
        # Add trigger for medical_bedrock_lambda (S3 Put trigger for audioEMR/transcript-txt)

        # Create Lambda function for DDBtoOpensearch
        ddb_to_opensearch_path = "lambda/DDBtoOpensearch,zip"
        ddb_to_opensearch_lambda = _lambda.Function(
            self, "DDBtoOpensearch",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(ddb_to_opensearch_path),  # Replace with your path
            timeout=core.Duration.minutes(3),
            role=ddb_to_opensearch_role,  # Assign the previously defined IAM role
            environment={
                "Opensearch_Username": username,
                "Opensearch_Password": password  # Example environment variable
            },
            layers=[requests_layer]
        )

        domain_endpoint = medical_domain.domain_enpoint
        ddb_to_opensearch_lambda.add_environment("Opensearch_URL", domain_endpoint)

        #Triggers
        transcript_to_txt_lambda.add_event_source(
            lambda_events.S3EventSource(
                bucket=medical_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix="audioEMR/transcript-txt/")]
            )
        )

        audio_to_transcribe_lambda.add_event_source(
            lambda_events.S3EventSource(
                bucket=medical_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix="audioEMR/raw-audio/")]
            )
        )

        transcript_to_txt_lambda.add_event_source(
            lambda_events.S3EventSource(
                bucket=medical_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix="audioEMR/transcribe-output/")]
            )
        )

        medical_bedrock_lambda.add_event_source(
            lambda_events.S3EventSource(
                bucket=medical_bucket,
                events=[s3.EventType.OBJECT_CREATED],
                filters=[s3.NotificationKeyFilter(prefix="textEMR/")]
            )
        )

        medical_table.add_stream(
            "MedicalTableStream",
            batch_size=1,
            target=ddb_to_opensearch_lambda
        )

def main():
    app = core.App()
    MedicalAnalysisStack(app, "MedicalAnalysisStack")
    app.synth()

if __name__ == "__main__":
    main()
