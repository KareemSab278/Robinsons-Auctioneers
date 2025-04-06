# Use an official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy everything
COPY . .

# Install dependencies
RUN pip install flask bcrypt

# Expose port
EXPOSE 10000

# Run the app
CMD ["python", "python.py"]
