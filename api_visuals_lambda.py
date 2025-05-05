import boto3
import pandas as pd
import plotly.express as px
import time
import io
import uuid

ATHENA_TABLE = "cloudtrail_logs_aws_cloudtrail_logs_471112829906_7bccabc1"
ATHENA_DATABASE = "default"  # Replace if different
ATHENA_QUERY_BUCKET = "my-athena-queries-1"
DASHBOARD_BUCKET = "api-dashboard-bucket55"

athena_client = boto3.client('athena')
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    query = f"""
    SELECT
      eventSource,
      userAgent,
      userIdentity.type AS principal_type,
      COALESCE(userIdentity.arn, 'UNKNOWN') AS principal,
      eventName,
      COUNT(*) AS frequency
    FROM {ATHENA_TABLE}
    WHERE eventTime BETWEEN '2025-05-01T00:00:00Z' AND '2025-06-01T00:00:00Z'
    GROUP BY eventSource, userAgent, userIdentity.type, COALESCE(userIdentity.arn, 'UNKNOWN'), eventName
    ORDER BY frequency DESC
    LIMIT 1000;
    """

    output_location = f's3://{ATHENA_QUERY_BUCKET}/query-results/'
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': ATHENA_DATABASE},
        ResultConfiguration={'OutputLocation': output_location}
    )

    query_execution_id = response['QueryExecutionId']

    # Wait for query to complete
    while True:
        result = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = result['QueryExecution']['Status']['State']
        if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            break
        time.sleep(2)

    if state != 'SUCCEEDED':
        raise Exception(f"Athena query failed: {state}")

    # Get the CSV result from S3
    result_key = f'query-results/{query_execution_id}.csv'
    csv_obj = s3_client.get_object(Bucket=ATHENA_QUERY_BUCKET, Key=result_key)
    df = pd.read_csv(io.BytesIO(csv_obj['Body'].read()))

    # Create a Plotly bar chart
    fig = px.bar(
        df,
        x='eventName',
        y='frequency',
        color='principal',
        hover_data=['eventSource', 'userAgent', 'principal_type'],
        title="Top AWS API Calls by Principal"
    )
    html_str = fig.to_html(full_html=True)

    # Save HTML to memory and upload
    html_key = f"dashboards/api_dashboard_{uuid.uuid4().hex[:8]}.html"
    s3_client.put_object(
        Bucket=DASHBOARD_BUCKET,
        Key=html_key,
        Body=html_str,
        ContentType='text/html'
    )

    # Optionally generate presigned URL
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': DASHBOARD_BUCKET, 'Key': html_key},
        ExpiresIn=3600  # 1 hour
    )

    return {
        'statusCode': 200,
        'body': f"Dashboard uploaded: {url}"
    }
