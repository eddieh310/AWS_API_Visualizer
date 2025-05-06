import boto3
import time
import csv
import io
from datetime import datetime

ATHENA_TABLE = "cloudtrail_logs_aws_cloudtrail_logs_471112829906_7bccabc1"
ATHENA_DATABASE = "default"
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

    # Download query result CSV
    result_key = f'query-results/{query_execution_id}.csv'
    result_obj = s3_client.get_object(Bucket=ATHENA_QUERY_BUCKET, Key=result_key)
    csv_bytes = result_obj['Body'].read()
    csv_str = csv_bytes.decode('utf-8')
    csv_reader = csv.reader(io.StringIO(csv_str))

    # Skip header row
    headers = next(csv_reader)

    # Extract top 5 rows
    top5 = list(csv_reader)[:5]

    # Format text summary
    summary_lines = ["Top 5 API Calls by IAM Principal:\n"]
    for i, row in enumerate(top5, 1):
        event_source, user_agent, principal_type, principal, event_name, frequency = row
        summary_lines.append(
            f"{i}. {event_name} ({frequency} times) - Principal: {principal} [{principal_type}]"
        )
    summary_text = "\n".join(summary_lines)

    # Save to S3 as a .txt file
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    txt_key = f"dashboard-summary/api_summary_{timestamp}.txt"

    s3_client.put_object(
        Bucket=DASHBOARD_BUCKET,
        Key=txt_key,
        Body=summary_text.encode("utf-8"),
        ContentType="text/plain"
    )


    return {
        'statusCode': 200,
        'message': 'Text summary created and uploaded successfully.'
    }
