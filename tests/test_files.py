import io
import os
import re
import tempfile
from glob import glob
from typing import Any, Generator

import boto3
import botocore.client
import moto
import pytest
from pytest_mock.plugin import MockerFixture

from axantir.files.schemas import File
from axantir.files.storage import FileStoreS3, FileStoreTempDirectory


@pytest.fixture
def binary_content() -> bytes:
    content = """
        d7b27252042793124e127adebffe0d856378fc94
        446437179dea68ca66a5bae01f249762486cdb56
        bb986be4ace64a79af65b2558fe2ece9e45f1d80
        120fdf95e94e1e2b0f55169f99d380c307b557c6
        df7443ad18aa6c2b41fc2fc044e8b3dd8c6eefcb
        f9722162234aa3c0b5685ff27c4d47968e82829a
        35764f6f8eb37e36d0a6efd509632a9f9ae544fd
        ccc9bd1f743b98176ab64cbbdda1705908a58546
        1498f63be773071fefe72c3f42bf3a905e57ca2f
        f667685796165759aa52bc7d6a705f78e437ad0e
        1665018f7d7f1d0ea3596d37955a47a1744790a7
        5bce0cc1806c5bec17e7f636c81d4b48cf990b73
        c8c82761ccd7a8563bffedb444eedb78b46f7d73
        3aadb7a01fbdaf1ca5b2937ce1e15c40ddf6a9e6
        68d63755832d9f44ae14f4f20746fcb89685fa02
        2c84e78120800b78b2e85d4de396cad14d0f1bac
        3afb17f2c8afbac8a6b9f6f70e294ff5b176c881
        70f37b6f14eaa679b23647a212c61aefd7ee66bd
        3f9e7915b48f4d44e2ccc73619de408e6a7bfd7e
        a4b5dcdcc7d11c6610f0aad588df6fdb7baa67b8
    """
    content = re.sub(r"\s*", "", content)
    return content.encode("utf8")


@pytest.fixture
def local_filestore() -> Generator[FileStoreTempDirectory, None, None]:
    with FileStoreTempDirectory() as filestore:
        yield filestore


@pytest.fixture(scope="module")
def aws_credentials() -> None:
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_TOKEN"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture(scope="module")
def aws_s3_client(aws_credentials: None) -> botocore.client.BaseClient:
    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="pytest")

        yield client


@pytest.fixture
def s3_file_store(
    aws_s3_client: botocore.client.BaseClient, mocker: MockerFixture
) -> FileStoreS3:
    mocker.patch("axantir.files.storage.boto3.client", return_value=aws_s3_client)
    return FileStoreS3(
        aws_region_name="test",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        s3_bucket_name="pytest",
    )


@pytest.mark.parametrize("filestore_fixture", ("local", "s3"))
@pytest.mark.parametrize("content_method", ("bytes", "bytesio", "filehandle"))
def test_filestore_bytes_rountrip(
    filestore_fixture: str,
    s3_file_store: FileStoreS3,
    local_filestore: FileStoreTempDirectory,
    binary_content: bytes,
    content_method: str,
) -> None:
    filestore = local_filestore if filestore_fixture == "local" else s3_file_store
    save_content: Any

    match content_method:
        case "bytes":
            save_content = binary_content
        case "bytesio":
            save_content = io.BytesIO(binary_content)
        case "filehandle":
            save_content = tempfile.TemporaryFile()
            save_content.write(binary_content)
            save_content.seek(0)

    file = File(name="boo")
    file = filestore.save_file(file, save_content)
    assert file.file_id
    assert file.mime_type == "text/plain"
    assert file.extension == ".txt"
    assert file.md5 == "86bec72d4a553bd52bc5f5cc04804565"
    assert file.size == 800
    assert file.name == "boo"
    assert file.file_name == "boo.txt"

    file_id = file.file_id

    file2 = filestore.get_file(file_id)
    assert file2
    assert file2.file_id == file_id
    assert file2.mime_type == "text/plain"
    assert file2.extension == ".txt"
    assert file2.md5 == "86bec72d4a553bd52bc5f5cc04804565"
    assert file2.size == 800
    assert file2.name == "boo"
    assert file2.file_name == "boo.txt"

    fh = filestore.get_content_filehandle(file2)
    assert fh

    assert fh.read() == binary_content


@pytest.mark.parametrize("filestore_fixture", ("local", "s3"))
def test_create_delete(
    filestore_fixture: str,
    s3_file_store: FileStoreS3,
    local_filestore: FileStoreTempDirectory,
    binary_content: bytes,
) -> None:
    filestore = local_filestore if filestore_fixture == "local" else s3_file_store
    file = File(name="boo")
    file = filestore.save_file(file, binary_content)
    assert file.file_id

    file_id = file.file_id

    filestore.delete_file(file)

    file2 = filestore.get_file(file_id)
    assert file2 is None
    assert filestore.get_content_filehandle(file) is None

    if isinstance(filestore, FileStoreTempDirectory):
        files = glob(f"{filestore.root_directory}/**", recursive=True)
        assert files == [filestore.root_directory + "/"]


@pytest.mark.parametrize("filestore_fixture", ("local", "s3"))
def test_get_fh_never_saved_file(
    filestore_fixture: str,
    s3_file_store: FileStoreS3,
    local_filestore: FileStoreTempDirectory,
) -> None:
    filestore = local_filestore if filestore_fixture == "local" else s3_file_store
    file = File(name="boo")
    assert file.file_id

    assert filestore.get_file(file.file_id) is None
    assert filestore.get_content_filehandle(file) is None


def test_s3_x_accel_off(s3_file_store: FileStoreS3, binary_content: bytes) -> None:
    file = File(name="boo")
    file = s3_file_store.save_file(file, binary_content)

    url = s3_file_store.get_file_content_remote_location(file)
    assert url is None


def test_s3_x_accel_on(s3_file_store: FileStoreS3, binary_content: bytes) -> None:
    s3_file_store.enable_remote_x_accel = True

    file = File(name="boo")
    file = s3_file_store.save_file(file, binary_content)
    assert file.file_id

    file_id = file.file_id

    url = s3_file_store.get_file_content_remote_location(file)
    assert url
    assert url.startswith("https://pytest.s3.amazonaws.com")
    assert "response-content-disposition=inline" in url
    assert file_id.hex in url


def test_s3_x_accel_on_as_attachment(
    s3_file_store: FileStoreS3, binary_content: bytes
) -> None:
    s3_file_store.enable_remote_x_accel = True

    file = File(name="boo")
    file = s3_file_store.save_file(file, binary_content)
    assert file.file_id

    file_id = file.file_id

    url = s3_file_store.get_file_content_remote_location(file, True)
    assert url
    assert url.startswith("https://pytest.s3.amazonaws.com")
    assert "response-content-disposition=attachment" in url
    assert file_id.hex in url
