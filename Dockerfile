FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    binutils \
    gdb \
    gcc \
    g++ \
    libc6-dev \
    make \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY requirements-dev.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 pwnuser && \
    chown -R pwnuser:pwnuser /app
USER pwnuser

# Create necessary directories
RUN mkdir -p /app/analysis_workspace /app/challenges /app/exploits

# Expose port for web interface
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["python", "web_pwn_analyzer.py", "--host", "0.0.0.0", "--port", "5000"]