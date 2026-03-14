# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY backend/requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app (backend, frontend, datasets)
COPY . .

# Expose the port your backend web application runs on (e.g., 5000 or 8000)
EXPOSE 8000

# Run the main entry point
CMD ["python", "backend/main.py"]