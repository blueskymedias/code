from flask import Flask, jsonify, request
import boto3
from flask_bcrypt import Bcrypt
import jwt
import datetime
import uuid
from flask import render_template

app = Flask(__name__)

# AWS Configuration
AWS_REGION = ''  # Replace with your region
AWS_ACCESS_KEY_ID = ''  # Replace with your key
AWS_SECRET_ACCESS_KEY = ''  # Replace with your secret key
print(f"Using region: {AWS_REGION}")

# Initialize AWS clients
dynamodb = boto3.resource(
    'dynamodb',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

rekognition = boto3.client(
    'rekognition',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# DynamoDB table names
USERS_TABLE = 'users'
USER_ANSWERS_TABLE = 'user_answers'

# JWT secret key
SECRET_KEY = "this is a secret key this is a secret keyyyy!!!!"

# Initialize Bcrypt
bcrypt = Bcrypt(app)

# Create DynamoDB tables if they don’t exist
def create_tables():
    # Users table
    try:
        dynamodb.create_table(
            TableName=USERS_TABLE,
            KeySchema=[{'AttributeName': 'username', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'username', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        ).wait_until_exists()
    except dynamodb.meta.client.exceptions.ResourceInUseException:
        pass

    # User Answers table with GSI for user_id
    try:
        dynamodb.create_table(
            TableName=USER_ANSWERS_TABLE,
            KeySchema=[{'AttributeName': 'user_answer_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'user_answer_id', 'AttributeType': 'S'},
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5},
            GlobalSecondaryIndexes=[{
                'IndexName': 'UserIdIndex',
                'KeySchema': [{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }]
        ).wait_until_exists()
    except dynamodb.meta.client.exceptions.ResourceInUseException:
        pass

create_tables()

# Password hashing functions
def encode_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)

# JWT token decoding
def decode_token(jwt_token):
    try:
        if jwt_token.startswith('Bearer '):
            jwt_token = jwt_token.split(' ')[1]
        return jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# Signup Endpoint
@app.route('/sign-up', methods=['POST'])
def signup():
    data = request.json
    username = data['username']
    password = data['password']
    hashed_password = encode_password(password)
    
    table = dynamodb.Table(USERS_TABLE)
    try:
        user_id = str(uuid.uuid4())  # Generate user_id
        response = table.put_item(
            Item={'username': username, 'password': hashed_password, 'user_id': user_id},
            ConditionExpression='attribute_not_exists(username)'
        )
        # Generate token after successful signup
        payload = {
            'username': username,
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({"message": "User registered successfully", "token": token}), 201
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return jsonify({"message": "Username already exists"}), 400

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    
    table = dynamodb.Table(USERS_TABLE)
    response = table.get_item(Key={'username': username})
    user = response.get('Item')
    
    if not user or not check_password(user['password'], password):
        return jsonify({"message": "Invalid username or password"}), 401
    
    payload = {
        'username': username,
        'user_id': user['user_id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return jsonify({"message": "Login successful", "token": token}), 200

# Analyze Image Endpoint with Detection Options
@app.route('/analyze-image', methods=['POST'])
def analyze_image():
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)
    if not decoded_token:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    user_id = decoded_token['user_id']
    
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400
    
    image_file = request.files['image']
    image_bytes = image_file.read()
    
    # Detection type argument (default to object detection)
    detection_type = request.form.get('detection_type', 'object').lower()
    question_id = request.form.get('question_id', f'{detection_type}_question_default')

    try:
        result_data = {}
        
        if detection_type == 'object':
            # Object Detection using detect_labels
            response = rekognition.detect_labels(
                Image={'Bytes': image_bytes},
                MaxLabels=10,
                MinConfidence=80
            )
            result_data['labels'] = [label['Name'] for label in response['Labels']]
        
        elif detection_type == 'text':
            # Text Detection using detect_text
            response = rekognition.detect_text(Image={'Bytes': image_bytes})
            result_data['text'] = [text['DetectedText'] for text in response['TextDetections']]
        
        elif detection_type == 'celebrity':
            # Celebrity Detection using recognize_celebrities
            response = rekognition.recognize_celebrities(Image={'Bytes': image_bytes})
            result_data['celebrities'] = [
                {
                    'name': celeb['Name'],
                    'confidence': celeb['MatchConfidence']
                } for celeb in response['CelebrityFaces']
            ]
        
        else:
            return jsonify({"error": "Invalid detection_type. Use 'object', 'text', or 'celebrity'"}), 400

        # Store in user_answers table
        user_answer_id = str(uuid.uuid4())
        table = dynamodb.Table(USER_ANSWERS_TABLE)
        table.put_item(
            Item={
                'user_answer_id': user_answer_id,
                'user_id': user_id,
                'question_id': question_id,
                'submitted_answer': f'{detection_type.capitalize()}-based answer',
                'image_results': str(result_data),  # Store as string for simplicity
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            "message": "Image analyzed and stored successfully",
            "detection_type": detection_type,
            "results": result_data,
            "user_answer_id": user_answer_id
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get Image Results Endpoint
@app.route('/get-image-results', methods=['GET'])
def get_image_results():
    jwt_token = request.headers.get('Authorization')
    decoded_token = decode_token(jwt_token)
    if not decoded_token:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    user_id = decoded_token['user_id']
    
    table = dynamodb.Table(USER_ANSWERS_TABLE)
    response = table.query(
        IndexName='UserIdIndex',
        KeyConditionExpression='user_id = :uid',
        ExpressionAttributeValues={':uid': user_id}
    )
    items = response.get('Items', [])
    
    results = [
        {
            'user_answer_id': item['user_answer_id'],
            'question_id': item['question_id'],
            'submitted_answer': item['submitted_answer'],
            'image_results': eval(item['image_results']),  # Convert string back to dict
            'timestamp': item['timestamp']
        } for item in items
    ]
    
    return jsonify({"results": results}), 200

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)