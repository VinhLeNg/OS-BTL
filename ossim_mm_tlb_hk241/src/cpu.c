
#include "cpu.h"
#include "mem.h"
#include "mm.h"

int calc(struct pcb_t * proc) {
	return ((unsigned long)proc & 0UL);
}

int alloc(struct pcb_t * proc, uint32_t size, uint32_t reg_index) {
	// hoho alloc
	// commit lan 2 ne
	addr_t addr = alloc_mem(size, proc);
	if (addr == 0) {
		return 1;
	}else{
		proc->regs[reg_index] = addr;
		return 0;
	}
}

int free_data(struct pcb_t * proc, uint32_t reg_index) {
	return free_mem(proc->regs[reg_index], proc);
}

int read(
		struct pcb_t * proc, // Process executing the instruction
		uint32_t source, // Index of source register
		uint32_t offset, // Source address = [source] + [offset]
		uint32_t destination) { // Index of destination register
	
	BYTE data;
	if (read_mem(proc->regs[source] + offset, proc,	&data)) {
		proc->regs[destination] = data;
		return 0;		
	}else{
		return 1;
	}
}

int write(
		struct pcb_t * proc, // Process executing the instruction
		BYTE data, // Data to be wrttien into memory
		uint32_t destination, // Index of destination register
		uint32_t offset) { 	// Destination address =
					// [destination] + [offset]
	return write_mem(proc->regs[destination] + offset, proc, data);
} 

int run(struct pcb_t * proc) {
	/* Check if Program Counter point to the proper instruction */
	if (proc->pc >= proc->code->size) {
		return 1;
	}
	
	struct inst_t ins = proc->code->text[proc->pc];
	proc->pc++;
	int stat = 1;
	switch (ins.opcode) {
	case CALC:
		stat = calc(proc);
		break;
	case ALLOC:
#ifdef CPU_TLB 
		stat = tlballoc(proc, ins.arg_0, ins.arg_1);
#elif defined(MM_PAGING)
		stat = pgalloc(proc, ins.arg_0, ins.arg_1);
#else
		stat = alloc(proc, ins.arg_0, ins.arg_1);
#endif
		break;
	case FREE:
#ifdef CPU_TLB
		stat = tlbfree_data(proc, ins.arg_0);
#elif defined(MM_PAGING)
		stat = pgfree_data(proc, ins.arg_0);
#else
		stat = free_data(proc, ins.arg_0);
#endif
		break;
	case READ:
#ifdef CPU_TLB
		stat = tlbread(proc, ins.arg_0, ins.arg_1, &ins.arg_2);
#elif defined(MM_PAGING)
		stat = pgread(proc, ins.arg_0, ins.arg_1, ins.arg_2);
#else
		stat = read(proc, ins.arg_0, ins.arg_1, ins.arg_2);
#endif
		break;
	case WRITE:
#ifdef CPU_TLB
		stat = tlbwrite(proc, ins.arg_0, ins.arg_1, ins.arg_2);
#elif defined(MM_PAGING)
		stat = pgwrite(proc, ins.arg_0, ins.arg_1, ins.arg_2);
#else
		stat = write(proc, ins.arg_0, ins.arg_1, ins.arg_2);
#endif
		break;
	default:
		stat = 1;
	}
	return stat;

}


