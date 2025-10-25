#!/bin/bash
# TerraSafe Infrastructure Setup Script
# This script sets up the complete infrastructure for TerraSafe

set -e  # Exit on error

echo "=========================================="
echo "TerraSafe Infrastructure Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found. Creating from .env.example..."
    cp .env.example .env
    print_info ".env file created. Please update it with your configuration."
    print_warning "⚠️  You must set TERRASAFE_API_KEY_HASH before continuing!"
    echo ""
    read -p "Press Enter to continue after updating .env file..."
fi

# Step 1: Generate API Key if needed
echo ""
echo "Step 1: API Key Setup"
echo "---------------------"
if grep -q "your-bcrypt-hash-here" .env; then
    print_warning "API key hash not configured!"
    echo ""
    read -p "Generate a new API key now? (y/n): " generate_key
    if [ "$generate_key" = "y" ] || [ "$generate_key" = "Y" ]; then
        print_info "Generating new API key..."
        python3 scripts/generate_api_key.py --random
        echo ""
        print_warning "Please update your .env file with the generated API_KEY_HASH"
        print_warning "Then run this script again."
        exit 0
    else
        print_error "Cannot proceed without API key hash. Exiting."
        exit 1
    fi
else
    print_info "API key hash already configured ✓"
fi

# Step 2: Start Docker services
echo ""
echo "Step 2: Starting Docker Services"
echo "--------------------------------"
print_info "Starting Redis and PostgreSQL..."
docker-compose up -d redis postgres

# Wait for services to be healthy
print_info "Waiting for services to be healthy..."
sleep 5

# Check Redis
if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    print_info "Redis is healthy ✓"
else
    print_error "Redis is not responding!"
    exit 1
fi

# Check PostgreSQL
if docker-compose exec -T postgres pg_isready -U terrasafe_user > /dev/null 2>&1; then
    print_info "PostgreSQL is healthy ✓"
else
    print_error "PostgreSQL is not responding!"
    exit 1
fi

# Step 3: Run Database Migrations
echo ""
echo "Step 3: Database Migrations"
echo "---------------------------"
print_info "Running Alembic migrations..."

# Check current migration status
current_version=$(alembic current 2>/dev/null || echo "none")
print_info "Current migration: $current_version"

# Run migrations
if alembic upgrade head; then
    print_info "Database migrations completed ✓"
else
    print_error "Migration failed!"
    exit 1
fi

# Verify migration
new_version=$(alembic current 2>/dev/null || echo "none")
print_info "New migration version: $new_version"

# Step 4: Start API and Monitoring Services
echo ""
echo "Step 4: Starting API and Monitoring"
echo "-----------------------------------"
print_info "Starting TerraSafe API, Prometheus, and Grafana..."
docker-compose up -d terrasafe-api prometheus grafana

print_info "Waiting for services to start..."
sleep 10

# Check API health
print_info "Checking API health..."
if curl -s http://localhost:8000/health > /dev/null; then
    print_info "TerraSafe API is healthy ✓"
else
    print_warning "API may not be ready yet. Check logs with: docker-compose logs terrasafe-api"
fi

# Step 5: Summary
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
print_info "Services Status:"
echo "  • Redis:        http://localhost:6379"
echo "  • PostgreSQL:   localhost:5432"
echo "  • API:          http://localhost:8000"
echo "  • API Docs:     http://localhost:8000/docs"
echo "  • Metrics:      http://localhost:8000/metrics"
echo "  • Prometheus:   http://localhost:9090"
echo "  • Grafana:      http://localhost:3000 (admin/admin)"
echo ""
print_info "Useful Commands:"
echo "  • View logs:           docker-compose logs -f"
echo "  • Stop services:       docker-compose down"
echo "  • Restart services:    docker-compose restart"
echo "  • Run tests:           pytest tests/ -v"
echo "  • Check migrations:    alembic current"
echo ""
print_info "Next Steps:"
echo "  1. Access Grafana at http://localhost:3000 (default: admin/admin)"
echo "  2. View the TerraSafe Overview dashboard"
echo "  3. Test the API with: curl http://localhost:8000/health"
echo "  4. Upload a Terraform file to scan via the API"
echo ""
print_info "Documentation: See README.md for full usage guide"
echo ""
