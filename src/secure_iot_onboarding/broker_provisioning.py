"""Mosquitto broker provisioning (ACL management) for device topics.

The Mosquitto ACL file format (simplified) supports lines like:

  user <username>
  topic readwrite devices/<device_id>/#

We treat the device's certificate Common Name (device UUID) as the broker username
when `use_identity_as_username true` is configured in Mosquitto.

This module adds/removes blocks for a device. Concurrency is controlled with a
file lock to avoid race conditions.
"""
from __future__ import annotations

from pathlib import Path
import fcntl
import tempfile
import os
from contextlib import contextmanager

ACL_FILE = Path(os.environ.get("MOSQUITTO_ACL_FILE", "./data/mosquitto.acl"))


def _ensure_acl_file():
	ACL_FILE.parent.mkdir(parents=True, exist_ok=True)
	ACL_FILE.touch(exist_ok=True)


@contextmanager
def _locked_file(path: Path, mode: str):
	_ensure_acl_file()
	with open(path, mode) as f:
		fcntl.flock(f, fcntl.LOCK_EX)
		try:
			yield f
		finally:
			fcntl.flock(f, fcntl.LOCK_UN)


def _device_block(device_id: str, topics):
	lines = [f"user {device_id}"]
	for t in topics:
		lines.append(f"topic readwrite {t}")
	return "\n".join(lines) + "\n"


def add_device_acl(device_id: str, topics):
	"""Add ACL entries for a device. Idempotent if block already exists."""
	block = _device_block(device_id, topics)
	with _locked_file(ACL_FILE, "r+") as f:
		content = f.read()
		if block in content:
			return
		# Append new block
		if not content.endswith("\n") and content:
			f.write("\n")
		f.write(block)


def remove_device_acl(device_id: str):
	"""Remove ACL block for a device if present."""
	with _locked_file(ACL_FILE, "r+") as f:
		content = f.read()
		lines = content.splitlines()
		new_lines = []
		skip = False
		for line in lines:
			if line.strip() == f"user {device_id}":
				skip = True
				continue
			if skip:
				if line.startswith("user "):
					# next block starts
					skip = False
					new_lines.append(line)
				else:
					# still skipping topic lines
					continue
			else:
				new_lines.append(line)
		new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
		f.seek(0)
		f.truncate(0)
		f.write(new_content)


__all__ = ["add_device_acl", "remove_device_acl"]

