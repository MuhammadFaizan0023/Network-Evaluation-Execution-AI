import os
import time
import csv
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

# Configuration
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "flows")
IOT_TOPIC = os.getenv("KAFKA_IOT_TOPIC", "flows_iot")
FLOWS_DIR = os.getenv("FLOWS_DIR", "/flows")
FLOWS_IOT_DIR = os.getenv("FLOWS_IOT_DIR", "/flows_iot")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "20"))
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "15"))

# Kafka settings
MAX_RETRIES = 10
RETRY_DELAY = 5

producer = None
for attempt in range(1, MAX_RETRIES + 1):
    try:
        print(f"Attempting to connect to Kafka (attempt {attempt}/{MAX_RETRIES})...")
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: v.encode("utf-8"),
            retries=5,
            max_block_ms=10000
        )
        print(f"Successfully connected to Kafka broker at {KAFKA_BROKER}")
        break
    except NoBrokersAvailable:
        if attempt < MAX_RETRIES:
            print(f"Kafka not available yet. Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
        else:
            print(f"Failed to connect to Kafka after {MAX_RETRIES} attempts. Exiting.")
            exit(1)

buffer = []
processed_files = set()

def send_batch(rows, target_topic):
    payload = "\n".join(rows)
    producer.send(target_topic, payload)
    producer.flush()
    print(f"Sent batch of {len(rows)} rows to Kafka topic '{target_topic}'")

print("Kafka CSV Producer started")
print(f"Watching directory: {FLOWS_DIR}")
print(f"Watching IoT directory: {FLOWS_IOT_DIR}")
print(f"Kafka broker: {KAFKA_BROKER}")
print(f"Default Topic: {TOPIC}")
print(f"IoT Topic: {IOT_TOPIC}")
print(f"Batch size: {BATCH_SIZE}")

def process_directory(directory, target_topic):
    if not os.path.isdir(directory):
        print(f"Directory not found: {directory}")
        return

    files = sorted(f for f in os.listdir(directory) if f.endswith(".csv"))

    for filename in files:
        filepath = os.path.join(directory, filename)

        if filepath in processed_files:
            continue

        print(f"Processing file: {filename}")
        file_buffer = []

        with open(filepath, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)

            for row in reader:
                file_buffer.append(",".join(row))

                if len(file_buffer) == BATCH_SIZE:
                    send_batch(file_buffer, target_topic)
                    file_buffer.clear()

        if file_buffer:
            send_batch(file_buffer, target_topic)

        processed_files.add(filepath)
        print(f"Finished processing: {filename} -> {target_topic}")

while True:
    try:
        process_directory(FLOWS_DIR, TOPIC)
        process_directory(FLOWS_IOT_DIR, IOT_TOPIC)
        time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\nShutdown signal received")
        break
    except Exception as e:
        print(f"Error: {e}")
        time.sleep(3)

producer.close()
print("Producer stopped cleanly")