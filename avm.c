#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <asm/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>

#include "alienvm.h"

int kfd, vmfd, vcfd;
size_t vcsz;
void *vcmap_raw;
struct kvm_run *run;

void *bios;
void *ram;
void *bmap;

int so_ifd;
int so_nfd;
int so_rqfd;
int so_rpfd;
uint32_t so_desc_ptr = 0;
uint32_t so_setup = 0;

int si_ifd;
int si_nfd;
int si_rqfd;
int si_rpfd;
uint32_t si_desc_ptr = 0;
uint32_t si_setup = 0;

int b_ifd;
int b_nfd;
int b_rqfd;
int b_rpfd;
uint32_t b_desc_ptr = 0;
uint32_t b_setup = 0;
uint32_t b_capacity = 0;

void error(const char *msg) {
	fprintf(stderr, "error: %s\n", msg);
	exit(127);
}

void check(bool cond, const char *msg) {
	if (!cond) {
		fprintf(stderr, "error: %s [%m]\n", msg);
		exit(127);
	}
}

uint64_t get_filesz(int fd) {
	struct stat s;
	int tmp = fstat(fd, &s);
	check(tmp == 0, "stat");
	return s.st_size;
}

int make_eventfd() {
	int res = eventfd(0, 0);
	check(res >= 0, "create eventfd");
	return res;
}

int make_irqfd(int irq) {
	int res = make_eventfd();
	struct kvm_irqfd irqfd = {
		.fd = res,
		.gsi = irq,
		.flags = 0,
	};
	int tmp = ioctl(vmfd, KVM_IRQFD, &irqfd);
	check(tmp == 0, "bind irqfd");
	return res;
}

int make_notifyfd(uint64_t addr) {
	int res = make_eventfd();
	struct kvm_ioeventfd ioeventfd = {
		.addr = addr,
		.len = 4,
		.fd = res,
		.flags = 0,
	};
	int tmp = ioctl(vmfd, KVM_IOEVENTFD, &ioeventfd);
	check(tmp == 0, "bind ioeventfd");
	return res;
}

void ev_send(int fd, eventfd_t val) {
	int tmp = eventfd_write(fd, val);
	check(tmp == 0, "ev send");
}

void ev_send1(int fd) {
	ev_send(fd, 1);
}

eventfd_t ev_recv(int fd) {
	eventfd_t res;
	int tmp = eventfd_read(fd, &res);
	check(tmp == 0, "ev recv");
	return res;
}

void ev_recv1(int fd) {
	check(ev_recv(fd) == 1, "ev_recv1");
}

void *serial_out_thread(void *p) {
	void *desc = 0;
	int npages = 0;
	void *pages[0x100];
	uint32_t get, put;
	while (1) {
		if (desc) {
			if (get != put) {
				int gpage = get >> AVM_PAGE_SHIFT;
				int goff = get & (AVM_PAGE_SIZE - 1);
				uint32_t num = (gpage + 1) * AVM_PAGE_SIZE - get;
				if (put > get && num > put - get)
					num = put - get;
				struct pollfd p[2] = {
					{.fd = 1, .events = POLLOUT},
					{.fd = so_rqfd, .events = POLLIN},
				};
				int tmp = poll(p, 2, -1);
				check(tmp > 0, "poll");
				if (p[1].revents)
					goto setup;
				check(p[0].revents == POLLOUT, "poll stdout");
				int n = write(1, pages[gpage] + goff, num);
				check(n > 0, "stdout write");
				get += n;
				if (get == npages * AVM_PAGE_SIZE)
					get = 0;
				// XXX fence
				*(volatile uint32_t *)(desc + AVM_SERIAL_OUT_DESC_GET) = get;
				ev_send1(so_ifd);
			} else {
				struct pollfd p[2] = {
					{.fd = so_nfd, .events = POLLIN},
					{.fd = so_rqfd, .events = POLLIN},
				};
				int tmp = poll(p, 2, -1);
				check(tmp > 0, "poll");
				if (p[1].revents)
					goto setup;
				check(p[0].revents == POLLIN, "poll nfd");
				ev_recv(so_nfd);
				put = *(volatile uint32_t *)(desc + AVM_SERIAL_OUT_DESC_PUT);
				if (put >= npages * AVM_PAGE_SIZE)
					error("serial out PUT out of range");
				// XXX fence?
			}
		} else {
setup:
			ev_recv1(so_rqfd);
			if (so_setup & AVM_MMIO_SERIAL_OUT_SETUP_ENABLE) {
				if (so_desc_ptr >= AVM_RAM_SIZE)
					error("serial out desc out of RAM");
				desc = ram + so_desc_ptr;
				npages = ((so_setup & AVM_MMIO_SERIAL_OUT_SETUP_NPAGES_M1_MASK) >> AVM_MMIO_SERIAL_OUT_SETUP_NPAGES_M1_SHIFT) + 1;
				get = *(uint32_t *)(desc + AVM_SERIAL_OUT_DESC_GET);
				put = *(uint32_t *)(desc + AVM_SERIAL_OUT_DESC_PUT);
				if (get >= npages * AVM_PAGE_SIZE)
					error("serial out GET out of range");
				if (put >= npages * AVM_PAGE_SIZE)
					error("serial out PUT out of range");
				for (int i = 0; i < npages; i++) {
					uint32_t ptr = *(uint32_t *)(desc + AVM_SERIAL_OUT_DESC_BUFFER_PTR(i));
					if (ptr & 0xfff)
						error("serial out unaligned page");
					if (ptr >= AVM_RAM_BASE && (ptr - AVM_RAM_BASE) < AVM_RAM_SIZE) {
						ptr -= AVM_RAM_BASE;
						pages[i] = ram + ptr;
					} else if (ptr >= AVM_BIOS_BASE && (ptr - AVM_BIOS_BASE) < AVM_BIOS_SIZE) {
						ptr -= AVM_BIOS_BASE;
						pages[i] = bios + ptr;
					} else {
						error("serial out page out of RAM / ROM");
					}
				}
			} else {
				desc = 0;
			}
			ev_send1(so_rpfd);
		}
	}
}

void *serial_in_thread(void *) {
	void *desc = 0;
	int npages = 0;
	void *pages[0x100];
	uint32_t get = 0, put = 0;
	while (1) {
		if (desc) {
			uint32_t nput = put + 1;
			if (nput == npages * AVM_PAGE_SIZE)
				nput = 0;
			if (nput != get) {
				int ppage = put >> AVM_PAGE_SHIFT;
				int poff = put & (AVM_PAGE_SIZE - 1);
				uint32_t num = (ppage + 1) * AVM_PAGE_SIZE - put;
				if (get > put && num > get - put - 1)
					num = get - put - 1;
				if (get == 0 && num > (npages * AVM_PAGE_SIZE) - put - 1)
					num = (npages * AVM_PAGE_SIZE) - put - 1;
				struct pollfd p[2] = {
					{.fd = 0, .events = POLLIN},
					{.fd = si_rqfd, .events = POLLIN},
				};
				int tmp = poll(p, 2, -1);
				check(tmp > 0, "poll");
				if (p[1].revents)
					goto setup;
				check(!(p[0].revents & ~(POLLIN|POLLHUP)), "poll stdin");
				int n = read(0, pages[ppage] + poff, num);
				check(n >= 0, "stdin read");
				if (n == 0) {
					// EOF.
					desc = 0;
					continue;
				}
				put += n;
				if (put == npages * AVM_PAGE_SIZE)
					put = 0;
				// XXX fence
				*(volatile uint32_t *)(desc + AVM_SERIAL_IN_DESC_PUT) = put;
				ev_send1(si_ifd);
			} else {
				struct pollfd p[2] = {
					{.fd = si_nfd, .events = POLLIN},
					{.fd = si_rqfd, .events = POLLIN},
				};
				int tmp = poll(p, 2, -1);
				check(tmp > 0, "poll");
				if (p[1].revents)
					goto setup;
				check(p[0].revents == POLLIN, "poll nfd");
				ev_recv(si_nfd);
				get = *(volatile uint32_t *)(desc + AVM_SERIAL_IN_DESC_GET);
				if (get >= npages * AVM_PAGE_SIZE)
					error("serial in GET out of range");
				// XXX fence?
			}
		} else {
setup:
			ev_recv1(si_rqfd);
			if (si_setup & AVM_MMIO_SERIAL_IN_SETUP_ENABLE) {
				if (si_desc_ptr >= AVM_RAM_SIZE)
					error("serial in desc out of RAM");
				desc = ram + si_desc_ptr;
				npages = ((si_setup & AVM_MMIO_SERIAL_IN_SETUP_NPAGES_M1_MASK) >> AVM_MMIO_SERIAL_IN_SETUP_NPAGES_M1_SHIFT) + 1;
				get = *(uint32_t *)(desc + AVM_SERIAL_IN_DESC_GET);
				put = *(uint32_t *)(desc + AVM_SERIAL_IN_DESC_PUT);
				if (get >= npages * AVM_PAGE_SIZE)
					error("serial in GET out of range");
				if (put >= npages * AVM_PAGE_SIZE)
					error("serial in PUT out of range");
				for (int i = 0; i < npages; i++) {
					uint32_t ptr = *(uint32_t *)(desc + AVM_SERIAL_IN_DESC_BUFFER_PTR(i));
					if (ptr & 0xfff)
						error("serial in unaligned page");
					if (ptr >= AVM_RAM_BASE && (ptr - AVM_RAM_BASE) < AVM_RAM_SIZE) {
						ptr -= AVM_RAM_BASE;
						pages[i] = ram + ptr;
					} else {
						error("serial in page out of RAM");
					}
				}
			} else {
				desc = 0;
			}
			ev_send1(si_rpfd);
		}
	}
}

void *block_thread(void *) {
	void *desc = 0;
	int nrequests = 0;
	uint32_t get, put;
	while (1) {
		if (desc) {
			if (get != put) {
				while (get != put) {
					uint32_t ptr = *(uint32_t *)(desc + AVM_BLOCK_DESC_REQ_BUFFER_PTR(get));
					if (ptr & 0xfff)
						error("block buffer unaligned page");
					if (ptr >= AVM_RAM_SIZE)
						error("block buffer out of RAM");
					void *block = ram + ptr;
					uint64_t bidx = *(uint32_t *)(desc + AVM_BLOCK_DESC_REQ_BLOCK_IDX(get));
					uint64_t off = bidx * AVM_PAGE_SIZE;
					uint32_t type = *(uint32_t *)(desc + AVM_BLOCK_DESC_REQ_TYPE(get));
					uint32_t status = AVM_BLOCK_DESC_REQ_STATUS_IO_ERROR;
					if (bidx >= b_capacity) {
						status = AVM_BLOCK_DESC_REQ_STATUS_INVALID_IDX;
					} else if (type == AVM_BLOCK_DESC_REQ_TYPE_READ) {
						memcpy(block, bmap + off, AVM_PAGE_SIZE);
						status = AVM_BLOCK_DESC_REQ_STATUS_SUCCESS;
					} else if (type == AVM_BLOCK_DESC_REQ_TYPE_WRITE) {
						memcpy(bmap + off, block, AVM_PAGE_SIZE);
						status = AVM_BLOCK_DESC_REQ_STATUS_SUCCESS;
					} else {
						status = AVM_BLOCK_DESC_REQ_STATUS_IO_ERROR;
					}
					*(uint32_t *)(desc + AVM_BLOCK_DESC_REQ_STATUS(get)) = status;
					get++;
					if (get == nrequests)
						get = 0;
				}
				// XXX fence
				*(volatile uint32_t *)(desc + AVM_BLOCK_DESC_GET) = get;
				ev_send1(b_ifd);
			} else {
				struct pollfd p[2] = {
					{.fd = b_nfd, .events = POLLIN},
					{.fd = b_rqfd, .events = POLLIN},
				};
				int tmp = poll(p, 2, -1);
				check(tmp > 0, "poll");
				if (p[1].revents)
					goto setup;
				check(p[0].revents == POLLIN, "poll nfd");
				ev_recv(b_nfd);
				put = *(volatile uint32_t *)(desc + AVM_BLOCK_DESC_PUT);
				if (put >= nrequests)
					error("block PUT out of range");
				// XXX fence?
			}
		} else {
setup:
			ev_recv1(b_rqfd);
			if (b_setup & AVM_MMIO_BLOCK_SETUP_ENABLE) {
				if (b_desc_ptr >= AVM_RAM_SIZE)
					error("block desc out of RAM");
				desc = ram + b_desc_ptr;
				nrequests = ((b_setup & AVM_MMIO_BLOCK_SETUP_NREQUESTS_M1_MASK) >> AVM_MMIO_BLOCK_SETUP_NREQUESTS_M1_SHIFT) + 1;
				get = *(uint32_t *)(desc + AVM_BLOCK_DESC_GET);
				put = *(uint32_t *)(desc + AVM_BLOCK_DESC_PUT);
				if (get >= nrequests)
					error("block GET out of range");
				if (put >= nrequests)
					error("block PUT out of range");
			} else {
				desc = 0;
			}
			ev_send1(b_rpfd);
		}
	}
}

int main(int argc, char **argv) {
	kfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	check(kfd >= 0, "open kvm");
	int vers = ioctl(kfd, KVM_GET_API_VERSION, 0);
	check(vers == 12, "unknown API version");
	long tmp = ioctl(kfd, KVM_GET_VCPU_MMAP_SIZE, 0);
	check(tmp >= 0, "vcpu get mmap size");
	vcsz = tmp;
	// printf("VCPU SIZE %zx\n", vcsz);

	vmfd = ioctl(kfd, KVM_CREATE_VM, 0);
	check(vmfd >= 0, "create vm");
	tmp = ioctl(vmfd, KVM_CREATE_IRQCHIP, 0);
	check(tmp == 0, "create irqchip");
	struct kvm_pit_config pit = {
		.flags = KVM_PIT_SPEAKER_DUMMY,
	};
	tmp = ioctl(vmfd, KVM_CREATE_PIT2, &pit);
	check(tmp == 0, "create pit");

	int bfd = open(argv[1], O_RDONLY);
	check(bfd >= 0, "open bios");
	uint64_t bsz = get_filesz(bfd);
	if (bsz != AVM_BIOS_SIZE)
		error("wrong bios size");
	bios = mmap(0, AVM_BIOS_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, bfd, 0);
	check(bios != MAP_FAILED, "mmap bios");
	ram = mmap(0, AVM_RAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	check(ram != MAP_FAILED, "mmap ram");
	struct kvm_userspace_memory_region ram_reg = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = AVM_RAM_BASE,
		.memory_size = AVM_RAM_SIZE,
		.userspace_addr = (uint64_t)ram,
	};
	tmp = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &ram_reg);
	check(tmp == 0, "add ram region");
	struct kvm_userspace_memory_region bios_reg = {
		.slot = 1,
		.flags = KVM_MEM_READONLY,
		.guest_phys_addr = AVM_BIOS_BASE,
		.memory_size = AVM_BIOS_SIZE,
		.userspace_addr = (uint64_t)bios,
	};
	tmp = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &bios_reg);
	check(tmp == 0, "add bios region");

	if (argc >= 3) {
		int blfd = open(argv[2], O_RDWR);
		check(blfd >= 0, "open block");
		uint64_t blsz = get_filesz(blfd);
		if (blsz & 0xfff)
			error("unaligned block dev size");
		b_capacity = blsz >> AVM_PAGE_SHIFT;
		bmap = mmap(0, b_capacity * AVM_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, blfd, 0);
		check(bmap != MAP_FAILED, "mmap block");
	}

	so_ifd = make_irqfd(AVM_IRQ_SERIAL_OUT);
	so_nfd = make_notifyfd(AVM_MMIO_SERIAL_OUT_NOTIFY);
	so_rqfd = make_eventfd();
	so_rpfd = make_eventfd();

	si_ifd = make_irqfd(AVM_IRQ_SERIAL_IN);
	si_nfd = make_notifyfd(AVM_MMIO_SERIAL_IN_NOTIFY);
	si_rqfd = make_eventfd();
	si_rpfd = make_eventfd();

	b_ifd = make_irqfd(AVM_IRQ_BLOCK);
	b_nfd = make_notifyfd(AVM_MMIO_BLOCK_NOTIFY);
	b_rqfd = make_eventfd();
	b_rpfd = make_eventfd();

	vcfd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
	check(vcfd >= 0, "create vcpu");
	struct kvm_cpuid2 *cpuid = malloc(sizeof *cpuid + sizeof (struct kvm_cpuid_entry2) * 0x200);
	cpuid->nent = 0x200;
	tmp = ioctl(kfd, KVM_GET_SUPPORTED_CPUID, cpuid);
	check(tmp == 0, "get supported cpuid");
	tmp = ioctl(vcfd, KVM_SET_CPUID2, cpuid);
	check(tmp == 0, "set cpuid");

	vcmap_raw = mmap(0, vcsz, PROT_READ | PROT_WRITE, MAP_SHARED, vcfd, 0);
	check(vcmap_raw != MAP_FAILED, "map vcpu");
	run = vcmap_raw;

	pthread_t thr;
	tmp = pthread_create(&thr, 0, serial_out_thread, 0);
	check(tmp == 0, "serial out thread");
	tmp = pthread_create(&thr, 0, serial_in_thread, 0);
	check(tmp == 0, "serial in thread");
	tmp = pthread_create(&thr, 0, block_thread, 0);
	check(tmp == 0, "block thread");

	while (1) {
		tmp = ioctl(vcfd, KVM_RUN, 0);
		check(tmp == 0, "kvm_run");
		switch (run->exit_reason) {
			case KVM_EXIT_IO: {
				void *data = (char *)vcmap_raw + run->io.data_offset;
				if (run->io.port == AVM_PORT_DEBUG_OUT && run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1) {
					fputc(*(char *)data, stderr);
				} else if (run->io.port == AVM_PORT_SHUTDOWN && run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1) {
					exit(*(char *)data);
				} else {
					printf("IO port %04x len %d mode %d val %016lx\n", run->io.port, run->io.size, run->io.direction, *(uint64_t *)data);
					return 127;
				}
				break;
			}
			case KVM_EXIT_MMIO: {
				if (run->mmio.len == 4 && run->mmio.is_write) {
					switch (run->mmio.phys_addr) {
						case AVM_MMIO_SERIAL_OUT_DESC_PTR:
							so_desc_ptr = *(uint32_t *)run->mmio.data & AVM_MMIO_SERIAL_OUT_DESC_PTR_MASK;
							break;
						case AVM_MMIO_SERIAL_OUT_SETUP:
							so_setup = *(uint32_t *)run->mmio.data & AVM_MMIO_SERIAL_OUT_SETUP_MASK;
							ev_send1(so_rqfd);
							ev_recv1(so_rpfd);
							break;
						case AVM_MMIO_SERIAL_IN_DESC_PTR:
							si_desc_ptr = *(uint32_t *)run->mmio.data & AVM_MMIO_SERIAL_IN_DESC_PTR_MASK;
							break;
						case AVM_MMIO_SERIAL_IN_SETUP:
							si_setup = *(uint32_t *)run->mmio.data & AVM_MMIO_SERIAL_IN_SETUP_MASK;
							ev_send1(si_rqfd);
							ev_recv1(si_rpfd);
							break;
						case AVM_MMIO_BLOCK_DESC_PTR:
							b_desc_ptr = *(uint32_t *)run->mmio.data & AVM_MMIO_BLOCK_DESC_PTR_MASK;
							break;
						case AVM_MMIO_BLOCK_SETUP:
							b_setup = *(uint32_t *)run->mmio.data & AVM_MMIO_BLOCK_SETUP_MASK;
							ev_send1(b_rqfd);
							ev_recv1(b_rpfd);
							break;
						default:
							goto mmio_oops;
					}
				} else if (run->mmio.len == 4 && !run->mmio.is_write) {
					switch (run->mmio.phys_addr) {
						case AVM_MMIO_SERIAL_OUT_DESC_PTR:
							*(uint32_t *)run->mmio.data = so_desc_ptr;
							break;
						case AVM_MMIO_SERIAL_OUT_SETUP:
							*(uint32_t *)run->mmio.data = so_setup;
							break;
						case AVM_MMIO_SERIAL_IN_DESC_PTR:
							*(uint32_t *)run->mmio.data = si_desc_ptr;
							break;
						case AVM_MMIO_SERIAL_IN_SETUP:
							*(uint32_t *)run->mmio.data = si_setup;
							break;
						case AVM_MMIO_BLOCK_DESC_PTR:
							*(uint32_t *)run->mmio.data = b_desc_ptr;
							break;
						case AVM_MMIO_BLOCK_SETUP:
							*(uint32_t *)run->mmio.data = b_setup;
							break;
						case AVM_MMIO_BLOCK_CAPACITY:
							*(uint32_t *)run->mmio.data = b_capacity;
							break;
						default:
							goto mmio_oops;
					}
				} else {
mmio_oops:
					printf("MMIO addr %08llx len %d mode %d val %016lx\n", run->mmio.phys_addr, run->mmio.len, run->mmio.is_write, *(uint64_t *)run->mmio.data);
					return 127;
				}
				break;
			}
			default: {
				printf("exit reason %d\n", run->exit_reason);
				return 127;
			}
		}
	}
}
