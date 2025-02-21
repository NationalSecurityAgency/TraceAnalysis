"""A schema for describing process behavior.

Currently ``spark`` only supports the strace format but we would like to extend
this be more generic across systems. The :doc:`spark.schema.events` submodule
describes the different events (namely syscalls) that can happen when a program
interacts with the linux kernel.
"""
