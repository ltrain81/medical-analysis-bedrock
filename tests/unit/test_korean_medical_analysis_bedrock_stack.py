import aws_cdk as core
import aws_cdk.assertions as assertions

from korean_medical_analysis_bedrock.korean_medical_analysis_bedrock_stack import KoreanMedicalAnalysisBedrockStack

# example tests. To run these tests, uncomment this file along with the example
# resource in korean_medical_analysis_bedrock/korean_medical_analysis_bedrock_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = KoreanMedicalAnalysisBedrockStack(app, "korean-medical-analysis-bedrock")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
