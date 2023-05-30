import hashlib
import json
import mimetypes
import os
import tempfile
import typing
import uuid
from abc import ABC, abstractmethod
from glob import glob
from typing import List, Optional

import boto3
import botocore.exceptions

from .schemas import BINARY_CONTENT_TYPE, File, utcnow
from .utils import get_file_mime_type


class FileStoreBase(ABC):
    def save_file(self, file_object: File, content: BINARY_CONTENT_TYPE) -> File:
        if not file_object.mime_type:
            file_object.mime_type = get_file_mime_type(content)

        if not file_object.extension:
            file_object.extension = (
                mimetypes.guess_extension(file_object.mime_type)
                if file_object.mime_type
                else None
            ) or None

        file_object.updated = utcnow()
        file_object = self._save_file_content(file_object, content)
        file_object = self._save_file_metadata(file_object)

        return file_object

    def delete_file(self, file_object: File) -> None:
        self._delete_file_metadata(file_object)
        self._delete_file_content(file_object)

    @abstractmethod
    def get_content_filehandle(
        self, file_object: File
    ) -> typing.Optional[typing.BinaryIO]:  # pragma: nocover
        """
        Find the content for a File object and return
        a readable filehandle for it.

        return None on object not found.
        """
        ...

    @abstractmethod
    def get_file(self, file_id: uuid.UUID) -> Optional[File]:  # pragma: nocover
        ...

    @abstractmethod
    def get_file_content_remote_location(
        self, file_object: File, as_attachment: bool = False
    ) -> typing.Optional[str]:  # pragma: nocover
        """
        Return a url suitable for X-Accel-Redirect or browser redirect
        to another location to retrieve the file data

        Arguments:

            file_object:    File object with all the metadata
            as_attachment:  If true, will try to return a url with attachment content disposition
        """
        ...

    @abstractmethod
    def _save_file_content(
        self, file_object: File, content: BINARY_CONTENT_TYPE
    ) -> File:  # pragma: nocover
        """
        Persist data for a File object

        Arguments:

            file_object:    File object with all the metadata
            content:        readable handle or bytes/bytearray of the data

        Use on an existing file will overwrite the original data.

        NOTE: file_object should be persisted BEFORE calling this and
        should be committed again afterwards as attributes in metadata
        may change during the save operation.
        """
        ...

    @abstractmethod
    def _save_file_metadata(self, file_object: File) -> File:  # pragma: nocover
        """
        Persist file metadata next to actual file content.  Is a backup
        to the database and makese sure that if files become orphans
        in the database, there is still a record of its metadata on disk
        next to the actual file data.

        RECORD: self.save_file is expected to call this after all metadata
        has been gathered

        Arguments:

            file_object:    File object with all the metadata

        NOTE: file_object should be persisted BEFORE calling this and
        should be committed again afterwards as attributes in metadata
        may change during the save operation.
        """
        ...

    @abstractmethod
    def _delete_file_content(self, file_object: File) -> None:  # pragma: nocover
        ...

    @abstractmethod
    def _delete_file_metadata(self, file_object: File) -> None:  # pragma: nocover
        ...


def split_uuid_for_path(id: uuid.UUID) -> List[str]:
    return str(id).split("-")


class FileStoreLocalDirectory(FileStoreBase):
    def __init__(self, root_directory: str) -> None:
        self.root_directory = root_directory

    def _get_content_path(self, file_object: File) -> str:
        root = os.path.join(
            self.root_directory,
            *split_uuid_for_path(file_object.file_id),
        )

        file_path = os.path.join(
            root,
            f"{file_object.file_id.hex}{file_object.extension or ''}",
        )
        return file_path

    def _get_metadata_path(self, file_object: File) -> str:
        return "".join([self._get_content_path(file_object), ".__meta__"])

    def _save_file_content(
        self, file_object: File, content: BINARY_CONTENT_TYPE
    ) -> File:
        path = self._get_content_path(file_object)
        os.makedirs(os.path.split(path)[0], exist_ok=True)
        with open(path, "wb") as fh:
            if isinstance(content, (bytes, bytearray)):
                file_object.md5 = hashlib.md5(content).hexdigest()
                file_object.size = fh.write(content)
            else:
                size = 0
                md5 = hashlib.md5()
                while True:
                    chunk = content.read(16384)
                    if not chunk:
                        break

                    md5.update(chunk)
                    size += fh.write(chunk)

                file_object.md5 = md5.hexdigest()
                file_object.size = size

        return file_object

    def _save_file_metadata(self, file_object: File) -> File:
        path = self._get_metadata_path(file_object)
        os.makedirs(os.path.split(path)[0], exist_ok=True)
        with open(path, "w") as fh:
            fh.write(file_object.json())

        return file_object

    def get_content_filehandle(
        self, file_object: File
    ) -> typing.Optional[typing.BinaryIO]:
        path = self._get_content_path(file_object)

        try:
            return open(path, "rb")
        except FileNotFoundError:
            return None

    def get_file(self, file_id: uuid.UUID) -> Optional[File]:
        # since we don't know extension, we have to go looking
        root = os.path.join(
            self.root_directory,
            *split_uuid_for_path(file_id),
        )
        candidates = glob(f"{root}/{file_id.hex}*.__meta__")
        if not candidates:
            return None

        path = candidates[0]
        with open(path, "r") as fh:
            data = json.loads(fh.read())
            return File(**data)

    def get_file_content_remote_location(
        self, file_object: File, as_attachment: bool = False
    ) -> typing.Optional[str]:
        return None

    def _delete_file_content(self, file_object: File) -> None:
        path = self._get_content_path(file_object)

        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

        self._clean_empty_path(path)

    def _delete_file_metadata(self, file_object: File) -> None:
        path = self._get_metadata_path(file_object)

        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

        self._clean_empty_path(path)

    def _clean_empty_path(self, path: str) -> None:
        root = self.root_directory
        if root.endswith("/"):
            root = root[:-1]

        while path:
            path = os.path.split(path)[0]
            if path == root:
                break

            try:
                os.rmdir(path)
            except OSError:
                break


class FileStoreTempDirectory(FileStoreLocalDirectory):
    """
    Context object meant for testing scenarios.  Will clean up stored data on destruction.

    Usage:
        @pytest.fixture
        def somefilestore() -> None:
            with FileStoreTempDirectory(<args for tempfile.TemporaryDirectory) as store:
                <set filestore on current app>
                yield
    """

    def __init__(self, **kwargs: typing.Any) -> None:
        self.tempdir = tempfile.TemporaryDirectory(**kwargs)
        super().__init__(root_directory=self.tempdir.name)

    def __enter__(self) -> "FileStoreTempDirectory":
        return self

    def __exit__(self, *args: list) -> None:
        if self.tempdir:
            self.tempdir.cleanup()


class FileStoreS3(FileStoreBase):
    """
    S3 Storage backend

    Requires policy actions:
        s3:PutObject
        s3:GetObject
        s3:GetObjectTagging
        s3:ListBucket
        s3:PutObjectTagging
        s3:DeleteObject
        s3:GetObjectVersion
    """

    def __init__(
        self,
        aws_region_name: str,
        s3_bucket_name: str,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        enable_remote_x_accel: bool = False,
        key_prefix: Optional[str] = None,
    ):
        self.s3_client = boto3.client(
            "s3",
            # endpoint_url only needs to be set for AWS S3 standins such as Minio
            # otherwise leave blank for the real AWS service (unless using S3
            # Transfer Acceleration)
            endpoint_url=endpoint_url,
            region_name=aws_region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        self.s3_bucket_name = s3_bucket_name
        self.enable_remote_x_accel = enable_remote_x_accel
        self.key_prefix = key_prefix

    def key_root(self, file_id: uuid.UUID) -> str:
        path_elements = []
        if self.key_prefix:
            path_elements.append(self.key_prefix)

        path_elements.extend(split_uuid_for_path(file_id))

        return "/".join(path_elements)

    def key_for_file(self, file_object: File) -> str:
        return "/".join(
            [
                self.key_root(file_object.file_id),
                f"{file_object.file_id.hex}{file_object.extension or ''}",
            ]
        )

    def key_for_metadata(self, file_id: uuid.UUID) -> str:
        return "/".join([self.key_root(file_id), f"{file_id.hex}.__meta__"])

    def _save_file_content(
        self, file_object: File, content: BINARY_CONTENT_TYPE
    ) -> File:
        key = self.key_for_file(file_object)
        self.s3_client.put_object(
            ACL="private",
            Body=content,
            Bucket=self.s3_bucket_name,
            ContentType=file_object.mime_type,
            Key=key,
            # ServerSideEncryption: This is handled via bucket policy
            StorageClass="STANDARD",
            # XXX: TODO
            # Tagging="???"
        )

        response = self.s3_client.head_object(
            Bucket=self.s3_bucket_name,
            Key=key,
        )
        file_object.size = response["ContentLength"]
        file_object.md5 = response["ETag"].strip('"')
        return file_object

    def _save_file_metadata(self, file_object: File) -> File:
        key = self.key_for_metadata(file_object.file_id)

        content = file_object.json()
        self.s3_client.put_object(
            ACL="private",
            Body=content,
            Bucket=self.s3_bucket_name,
            ContentType="application/json",
            Key=key,
            # ServerSideEncryption: This is handled via bucket policy
            StorageClass="STANDARD",
            # XXX: TODO
            # Tagging="???"
        )
        return file_object

    def get_file(self, file_id: uuid.UUID) -> Optional[File]:
        metadata_key = self.key_for_metadata(file_id)
        try:
            response = self.s3_client.get_object(
                Bucket=self.s3_bucket_name,
                Key=metadata_key,
            )
            return File(**json.loads(response["Body"].read()))
        except botocore.exceptions.ClientError as ex:
            if ex.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise

    def get_content_filehandle(
        self, file_object: File
    ) -> typing.Optional[typing.BinaryIO]:
        key = self.key_for_file(file_object)
        try:
            response = self.s3_client.get_object(
                Bucket=self.s3_bucket_name,
                Key=key,
                # IfModifiedSince
            )
            return response["Body"]
        except botocore.exceptions.ClientError as ex:
            if ex.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise

    def get_file_content_remote_location(
        self, file_object: File, as_attachment: bool = False
    ) -> typing.Optional[str]:
        if not self.enable_remote_x_accel:
            return None

        key = self.key_for_file(file_object)
        response = self.s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.s3_bucket_name,
                "Key": key,
                "ResponseContentDisposition": (
                    f'attachment; filename="{file_object.file_name}"'
                    if as_attachment
                    else "inline"
                ),
            },
            ExpiresIn=120,
        )
        return response

    def _delete_file_content(self, file_object: File) -> None:
        key = self.key_for_file(file_object)
        self.s3_client.delete_object(Bucket=self.s3_bucket_name, Key=key)

    def _delete_file_metadata(self, file_object: File) -> None:
        key = self.key_for_metadata(file_object.file_id)
        self.s3_client.delete_object(Bucket=self.s3_bucket_name, Key=key)
