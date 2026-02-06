import multiprocessing
from tqdm import tqdm

def multiprocess(worker_args, func, max_workers=4, show_progress=True):
    """
     func worker_args
    :param worker_args:  [(arg1,), (arg2,), ...]  [arg1, arg2, ...]
    :param func: 
    :param max_workers: 
    :param show_progress: 
    :return: 
    """
    with multiprocessing.Pool(processes=max_workers) as pool:
        if show_progress:
            results = list(tqdm(pool.imap(func, worker_args), total=len(worker_args)))
        else:
            results = pool.map(func, worker_args)
    return results
