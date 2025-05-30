import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from fastapi.testclient import TestClient

# Sample test data
mock_profiles = [
    {"id": 1, "name": "John Doe", "login": "johndoe"},
    {"id": 2, "name": "Jane Smith", "login": "janesmith"},
    {"id": 3, "name": "John Smith", "login": "johnsmith"},
    {"id": 4, "name": "Alice Johnson", "login": "alicejohn"}
]


# Mock supabase client
@pytest.fixture(scope="module", autouse=True)
def mock_supabase_client():
    """
    Mock the Supabase client creation before importing any app modules.
    This prevents the actual Supabase client from being created during import.
    """
    with patch("supabase._sync.client.SyncClient.create") as mock_create:
        mock_client = MagicMock()
        mock_create.return_value = mock_client
        yield mock_client


# Mock environment variables
@pytest.fixture(scope="module", autouse=True)
def mock_env_vars():
    """Mock environment variables to prevent actual env lookups"""
    with patch.dict("os.environ", {
        "SUPABASE_URL": "https://fake-supabase-url.com",
        "SUPABASE_SERVICE_ROLE_KEY": "fake-supabase-key"
    }):
        yield


# We need to import the module after the fixtures have been applied
@pytest.fixture
def profiles_router():
    # Import the router only after mocking
    from routes.profile_routes.search_profile_router import router, search_profiles
    return router, search_profiles


@pytest.fixture
def test_client(profiles_router):
    # Import FastAPI app
    from main import app
    return TestClient(app)


class TestSearchProfiles:
    """Tests for the search_profiles function and endpoint"""

    def test_search_profiles_by_name(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock responses
        name_mock = MagicMock()
        name_mock.data = [mock_profiles[0], mock_profiles[2]]  # John Doe and John Smith

        login_mock = MagicMock()
        login_mock.data = []  # No login matches

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Execute the function
        result = search_profiles(query="John", limit=10, offset=0)

        # Assertions
        assert len(result) == 2
        assert result[0]["name"] == "John Doe"
        assert result[1]["name"] == "John Smith"

        # Verify the calls
        mock_supabase_client.table.assert_called_with("user_profiles")
        table_mock.select.assert_called_with("*")

    def test_search_profiles_by_login(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock responses
        name_mock = MagicMock()
        name_mock.data = []  # No name matches

        login_mock = MagicMock()
        login_mock.data = [mock_profiles[0], mock_profiles[3]]  # johndoe and alicejohn

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Execute the function
        result = search_profiles(query="john", limit=10, offset=0)

        # Assertions
        assert len(result) == 2
        assert result[0]["login"] == "johndoe"
        assert result[1]["login"] == "alicejohn"

    def test_search_profiles_with_duplicates(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock responses - same profile appears in both name and login results
        name_mock = MagicMock()
        name_mock.data = [mock_profiles[0]]  # John Doe

        login_mock = MagicMock()
        login_mock.data = [mock_profiles[0]]  # johndoe (same as John Doe)

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Execute the function
        result = search_profiles(query="john", limit=10, offset=0)

        # Assertions
        assert len(result) == 1  # Should deduplicate
        assert result[0]["name"] == "John Doe"
        assert result[0]["login"] == "johndoe"

    def test_search_profiles_with_limit_and_offset(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock responses
        name_mock = MagicMock()
        name_mock.data = [mock_profiles[1]]  # Jane (with offset, assuming John was skipped)

        login_mock = MagicMock()
        login_mock.data = []

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Execute the function with limit=1 and offset=1
        result = search_profiles(query="j", limit=1, offset=1)

        # Assertions
        assert len(result) == 1
        assert result[0]["name"] == "Jane Smith"

        # Verify the calls used correct limit and offset
        ilike_mock.limit.assert_called_with(1)
        limit_mock.offset.assert_called_with(1)

    def test_search_profiles_no_results(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock responses - no matches for either search
        name_mock = MagicMock()
        name_mock.data = []

        login_mock = MagicMock()
        login_mock.data = []

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Execute the function
        result = search_profiles(query="nonexistent", limit=10, offset=0)

        # Assertions
        assert len(result) == 0
        assert result == []

    def test_search_profiles_database_error(self, mock_supabase_client, profiles_router):
        # Get search_profiles function from fixture
        _, search_profiles = profiles_router

        # Setup mock to raise an exception
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = Exception("Database error")

        # Execute the function and expect an HTTPException
        with pytest.raises(HTTPException) as excinfo:
            search_profiles(query="john", limit=10, offset=0)

        # Verify exception details
        assert excinfo.value.status_code == 500
        assert "Error searching profiles" in str(excinfo.value.detail)

    def test_search_profiles_endpoint_success(self, mock_supabase_client, test_client):
        # Setup mock responses
        name_mock = MagicMock()
        name_mock.data = [mock_profiles[0]]  # John Doe

        login_mock = MagicMock()
        login_mock.data = []

        # Setup mock chain for supabase client
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = [name_mock, login_mock]

        # Call the endpoint
        response = test_client.get("/profiles/search?query=John&limit=10&offset=0")

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "John Doe"

    def test_search_profiles_endpoint_validation_error(self, test_client):
        # Query parameter is required - should return 422 when missing
        response = test_client.get("/profiles/search?limit=10&offset=0")
        assert response.status_code == 422

        # Query parameter must not be empty
        response = test_client.get("/profiles/search?query=&limit=10&offset=0")
        assert response.status_code == 422

        # Limit must be between 1 and 100
        response = test_client.get("/profiles/search?query=John&limit=0&offset=0")
        assert response.status_code == 422

        response = test_client.get("/profiles/search?query=John&limit=101&offset=0")
        assert response.status_code == 422

        # Offset must be >= 0
        response = test_client.get("/profiles/search?query=John&limit=10&offset=-1")
        assert response.status_code == 422

    def test_search_profiles_endpoint_server_error(self, mock_supabase_client, test_client):
        # Setup mock to raise an exception
        table_mock = MagicMock()
        select_mock = MagicMock()
        ilike_mock = MagicMock()
        limit_mock = MagicMock()
        offset_mock = MagicMock()

        mock_supabase_client.table.return_value = table_mock
        table_mock.select.return_value = select_mock
        select_mock.ilike.return_value = ilike_mock
        ilike_mock.limit.return_value = limit_mock
        limit_mock.offset.return_value = offset_mock
        offset_mock.execute.side_effect = Exception("Database error")

        # Call the endpoint
        response = test_client.get("/profiles/search?query=John&limit=10&offset=0")

        # Assertions
        assert response.status_code == 500
        assert "Error searching profiles" in response.json()["detail"]